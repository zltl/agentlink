//! X11 capture through MIT-SHM (with an XGetImage fallback) and XTest input.

use std::time::Duration;

use x11rb::connection::Connection;
use x11rb::protocol::damage::{ConnectionExt as _, ReportLevel};
use x11rb::protocol::randr::ConnectionExt as _;
use x11rb::protocol::shm::ConnectionExt as _;
use x11rb::protocol::xfixes::ConnectionExt as _;
use x11rb::protocol::xproto::{
    Atom, AtomEnum, ChangeWindowAttributesAux, ConnectionExt as _, EventMask, ImageFormat, Keycode,
    Window,
};
use x11rb::protocol::xtest::ConnectionExt as _;
use x11rb::rust_connection::RustConnection;

use crate::capture::{check_pixels, Frame, MonitorInfo, Rect};
use crate::error::{msg, Result};
use crate::input::{MouseButton, Pointer};
use crate::keys::key_info;

const KEY_PRESS: u8 = 2;
const KEY_RELEASE: u8 = 3;
const BUTTON_PRESS: u8 = 4;
const BUTTON_RELEASE: u8 = 5;
const MOTION_NOTIFY: u8 = 6;

pub struct X11Desk {
    conn: RustConnection,
    screen: usize,
    root: Window,
    width: u32,
    height: u32,
    shm: Option<ShmSlot>,
    shm_ok: bool,
    keymap: Option<Keymap>,
    xwayland: bool,
    damage: Option<DamageWatch>,
}

struct DamageWatch {
    damage: u32,
    region: u32,
    primed: bool,
}

struct ShmSlot {
    seg: u32,
    ptr: *mut libc::c_void,
    size: usize,
}

struct Keymap {
    min: u8,
    per: usize,
    syms: Vec<u32>,
}

impl X11Desk {
    pub fn connect() -> Result<Self> {
        let (conn, screen) =
            x11rb::connect(None).map_err(|err| msg(format!("X11 connect: {err}")))?;
        let setup = conn.setup();
        let root_info = setup
            .roots
            .get(screen)
            .ok_or_else(|| msg("X11 screen index is out of range"))?;
        let root = root_info.root;
        let width = root_info.width_in_pixels as u32;
        let height = root_info.height_in_pixels as u32;
        let shm_ok = conn
            .query_extension(b"MIT-SHM")
            .ok()
            .and_then(|cookie| cookie.reply().ok())
            .map(|reply| reply.present)
            .unwrap_or(false);
        let xtest = conn
            .query_extension(b"XTEST")
            .ok()
            .and_then(|cookie| cookie.reply().ok())
            .map(|reply| reply.present)
            .unwrap_or(false);
        if !xtest {
            tracing::warn!("XTEST extension is missing; keyboard and mouse injection will fail");
        }
        let xwayland = conn
            .query_extension(b"XWAYLAND")
            .ok()
            .and_then(|cookie| cookie.reply().ok())
            .map(|reply| reply.present)
            .unwrap_or(false);
        // Some servers deliver events only after the client selects them.
        let _ = conn.change_window_attributes(
            root,
            &ChangeWindowAttributesAux::new().event_mask(EventMask::STRUCTURE_NOTIFY),
        );
        let _ = conn.flush();
        Ok(Self {
            conn,
            screen,
            root,
            width,
            height,
            shm: None,
            shm_ok,
            keymap: None,
            xwayland,
            damage: None,
        })
    }

    /// `Ok(true)` when something changed (or damage is unavailable, so the
    /// caller must copy). `Ok(false)` when the screen is static.
    pub fn screen_changed(&mut self) -> bool {
        if self.damage.is_none() && !self.arm_damage() {
            return true;
        }
        let Some(watch) = self.damage.as_mut() else {
            return true;
        };
        if !watch.primed {
            watch.primed = true;
            return true;
        }
        let damage = watch.damage;
        let region = watch.region;
        if self
            .conn
            .damage_subtract(damage, x11rb::NONE, region)
            .is_err()
        {
            return true;
        }
        if self.conn.flush().is_err() {
            return true;
        }
        let Ok(cookie) = self.conn.xfixes_fetch_region(region) else {
            return true;
        };
        let Ok(reply) = cookie.reply() else {
            return true;
        };
        !reply.rectangles.is_empty()
    }

    fn arm_damage(&mut self) -> bool {
        let damage_ok = self
            .conn
            .query_extension(b"DAMAGE")
            .ok()
            .and_then(|cookie| cookie.reply().ok())
            .map(|reply| reply.present)
            .unwrap_or(false);
        let fixes_ok = self
            .conn
            .query_extension(b"XFIXES")
            .ok()
            .and_then(|cookie| cookie.reply().ok())
            .map(|reply| reply.present)
            .unwrap_or(false);
        if !damage_ok || !fixes_ok {
            return false;
        }
        let _ = self.conn.xfixes_query_version(5, 0);
        let _ = self.conn.damage_query_version(1, 1);
        let Ok(damage) = self.conn.generate_id() else {
            return false;
        };
        let Ok(region) = self.conn.generate_id() else {
            return false;
        };
        if self
            .conn
            .damage_create(damage, self.root, ReportLevel::RAW_RECTANGLES)
            .is_err()
        {
            return false;
        }
        if self.conn.xfixes_create_region(region, &[]).is_err() {
            return false;
        }
        let _ = self.conn.flush();
        self.damage = Some(DamageWatch {
            damage,
            region,
            primed: false,
        });
        true
    }

    pub fn pointer(&self) -> Option<(i32, i32)> {
        let reply = self.conn.query_pointer(self.root).ok()?.reply().ok()?;
        Some((reply.root_x as i32, reply.root_y as i32))
    }

    pub fn is_xwayland(&self) -> bool {
        self.xwayland
    }

    pub fn backend_name(&self) -> &'static str {
        if self.shm_ok {
            "x11-shm"
        } else {
            "x11-getimage"
        }
    }

    pub fn monitors(&self) -> Result<Vec<MonitorInfo>> {
        if let Some(monitors) = self.randr_monitors() {
            if !monitors.is_empty() {
                return Ok(monitors);
            }
        }
        Ok(vec![MonitorInfo {
            index: 0,
            name: "x11-0".into(),
            x: 0,
            y: 0,
            width: self.width,
            height: self.height,
            primary: true,
        }])
    }

    fn randr_monitors(&self) -> Option<Vec<MonitorInfo>> {
        let present = self
            .conn
            .query_extension(b"RANDR")
            .ok()?
            .reply()
            .ok()?
            .present;
        if !present {
            return None;
        }
        let resources = self
            .conn
            .randr_get_screen_resources_current(self.root)
            .ok()?
            .reply()
            .ok()?;
        let mut monitors = Vec::new();
        for crtc in resources.crtcs {
            let info = self.conn.randr_get_crtc_info(crtc, 0).ok()?.reply().ok()?;
            if info.mode == 0 || info.width == 0 || info.height == 0 {
                continue;
            }
            let index = monitors.len() as u32;
            monitors.push(MonitorInfo {
                index,
                name: format!("x11-{index}"),
                x: info.x as i32,
                y: info.y as i32,
                width: info.width as u32,
                height: info.height as u32,
                primary: info.x == 0 && info.y == 0,
            });
        }
        if !monitors.iter().any(|monitor| monitor.primary) {
            if let Some(first) = monitors.first_mut() {
                first.primary = true;
            }
        }
        Some(monitors)
    }

    pub fn capture_full(&mut self) -> Result<Frame> {
        self.grab(self.root, 0, 0, self.width, self.height)
    }

    pub fn capture_monitor(&mut self, index: u32) -> Result<Frame> {
        let monitor = self
            .monitors()?
            .into_iter()
            .find(|monitor| monitor.index == index)
            .ok_or_else(|| msg(format!("monitor {index} does not exist")))?;
        self.grab(
            self.root,
            monitor.x as i16,
            monitor.y as i16,
            monitor.width,
            monitor.height,
        )
    }

    pub fn capture_region(&mut self, rect: Rect) -> Result<Frame> {
        if rect.x < 0 || rect.y < 0 {
            return Err(msg("X11 region coordinates must be non-negative"));
        }
        self.grab(
            self.root,
            i16::try_from(rect.x).map_err(|_| msg("region x does not fit in i16"))?,
            i16::try_from(rect.y).map_err(|_| msg("region y does not fit in i16"))?,
            rect.width,
            rect.height,
        )
    }

    pub fn capture_window(&mut self, query: &str) -> Result<Frame> {
        let window = self.find_window(query)?;
        let geom = self
            .conn
            .get_geometry(window)
            .map_err(|err| msg(err.to_string()))?
            .reply()
            .map_err(|err| msg(err.to_string()))?;
        self.grab(window, 0, 0, geom.width as u32, geom.height as u32)
    }

    fn grab(&mut self, drawable: Window, x: i16, y: i16, width: u32, height: u32) -> Result<Frame> {
        check_pixels(width, height)?;
        let (width, height) = (
            u16::try_from(width).map_err(|_| msg("capture width exceeds 65535"))?,
            u16::try_from(height).map_err(|_| msg("capture height exceeds 65535"))?,
        );
        if self.shm_ok {
            match self.grab_shm(drawable, x, y, width, height) {
                Ok(frame) => return Ok(frame),
                Err(err) => {
                    tracing::warn!(error = %err, "MIT-SHM capture failed; falling back to GetImage");
                    self.shm_ok = false;
                }
            }
        }
        self.grab_getimage(drawable, x, y, width, height)
    }

    fn grab_shm(
        &mut self,
        drawable: Window,
        x: i16,
        y: i16,
        width: u16,
        height: u16,
    ) -> Result<Frame> {
        let bpp = self.bytes_per_pixel()?;
        let stride = width as usize * bpp;
        let size = stride * height as usize;
        self.ensure_shm(size)?;
        let seg = self.shm.as_ref().unwrap().seg;
        let reply = self
            .conn
            .shm_get_image(
                drawable,
                x,
                y,
                width,
                height,
                !0,
                u8::from(ImageFormat::Z_PIXMAP),
                seg,
                0,
            )
            .map_err(|err| msg(format!("shm get image: {err}")))?
            .reply()
            .map_err(|err| msg(format!("shm get image: {err}")))?;
        let ptr = self.shm.as_ref().unwrap().ptr;
        // The X server wrote the image into the shared mapping. Copy it out
        // once so the next grab can reuse the segment.
        let bytes = unsafe { std::slice::from_raw_parts(ptr as *const u8, size) }.to_vec();
        pack_ximage(
            &bytes,
            width as u32,
            height as u32,
            stride as u32,
            bpp,
            self.lsb_first(),
            reply.depth,
            self.backend_name(),
        )
    }

    fn grab_getimage(
        &mut self,
        drawable: Window,
        x: i16,
        y: i16,
        width: u16,
        height: u16,
    ) -> Result<Frame> {
        let reply = self
            .conn
            .get_image(ImageFormat::Z_PIXMAP, drawable, x, y, width, height, !0)
            .map_err(|err| msg(format!("XGetImage: {err}")))?
            .reply()
            .map_err(|err| msg(format!("XGetImage: {err}")))?;
        let bpp = self.bytes_per_pixel().unwrap_or(4);
        let stride = if reply.data.len() >= width as usize * height as usize && height > 0 {
            reply.data.len() / height as usize
        } else {
            width as usize * bpp
        };
        pack_ximage(
            &reply.data,
            width as u32,
            height as u32,
            stride as u32,
            bpp,
            self.lsb_first(),
            reply.depth,
            "x11-getimage",
        )
    }

    fn ensure_shm(&mut self, size: usize) -> Result<()> {
        if self
            .shm
            .as_ref()
            .map(|slot| slot.size >= size)
            .unwrap_or(false)
        {
            return Ok(());
        }
        self.drop_shm();
        let seg = self
            .conn
            .generate_id()
            .map_err(|err| msg(format!("X11 id: {err}")))?;
        let shmid = unsafe { libc::shmget(libc::IPC_PRIVATE, size, libc::IPC_CREAT | 0o600) };
        if shmid < 0 {
            return Err(msg(format!(
                "shmget failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let ptr = unsafe { libc::shmat(shmid, std::ptr::null(), 0) };
        if ptr as isize == -1 {
            return Err(msg(format!(
                "shmat failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        // Detach the id from the kernel namespace now; the mapping stays until shmdt.
        unsafe {
            libc::shmctl(shmid, libc::IPC_RMID, std::ptr::null_mut());
        }
        if let Err(err) = self
            .conn
            .shm_attach(seg, shmid as u32, false)
            .map_err(|err| msg(err.to_string()))
            .and_then(|cookie| cookie.check().map_err(|err| msg(err.to_string())))
        {
            unsafe { libc::shmdt(ptr) };
            return Err(err);
        }
        self.shm = Some(ShmSlot { seg, ptr, size });
        Ok(())
    }

    fn drop_shm(&mut self) {
        if let Some(slot) = self.shm.take() {
            let _ = self.conn.shm_detach(slot.seg);
            let _ = self.conn.flush();
            unsafe { libc::shmdt(slot.ptr) };
        }
    }

    fn bytes_per_pixel(&self) -> Result<usize> {
        let screen = &self.conn.setup().roots[self.screen];
        let depth = screen.root_depth;
        let format = self
            .conn
            .setup()
            .pixmap_formats
            .iter()
            .find(|format| format.depth == depth)
            .ok_or_else(|| msg(format!("no pixmap format for depth {depth}")))?;
        let bpp = format.bits_per_pixel as usize / 8;
        if bpp == 0 {
            return Err(msg("X11 pixmap format has a zero bits-per-pixel"));
        }
        Ok(bpp)
    }

    fn lsb_first(&self) -> bool {
        self.conn.setup().image_byte_order == x11rb::protocol::xproto::ImageOrder::LSB_FIRST
    }

    fn find_window(&self, query: &str) -> Result<Window> {
        if let Ok(id) = query.parse::<u32>() {
            return Ok(id);
        }
        let client_list = self.atom("_NET_CLIENT_LIST")?;
        let windows = self.property_windows(self.root, client_list)?;
        let query_l = query.to_ascii_lowercase();
        for window in windows {
            let name = self.window_name(window);
            if name.to_ascii_lowercase().contains(&query_l) {
                return Ok(window);
            }
        }
        Err(msg(format!("no X11 window matches '{query}'")))
    }

    fn window_name(&self, window: Window) -> String {
        if let Ok(atom) = self.atom("_NET_WM_NAME") {
            if let Some(text) = self.property_string(window, atom) {
                return text;
            }
        }
        self.property_string(window, AtomEnum::WM_NAME.into())
            .unwrap_or_default()
    }

    fn property_string(&self, window: Window, property: Atom) -> Option<String> {
        let reply = self
            .conn
            .get_property(false, window, property, AtomEnum::ANY, 0, 1024)
            .ok()?
            .reply()
            .ok()?;
        if reply.value.is_empty() {
            return None;
        }
        let bytes = reply
            .value
            .split(|byte| *byte == 0)
            .next()
            .unwrap_or(&reply.value);
        Some(String::from_utf8_lossy(bytes).trim().to_string())
    }

    fn property_windows(&self, window: Window, property: Atom) -> Result<Vec<Window>> {
        let reply = self
            .conn
            .get_property(false, window, property, AtomEnum::WINDOW, 0, 4096)
            .map_err(|err| msg(err.to_string()))?
            .reply()
            .map_err(|err| msg(err.to_string()))?;
        Ok(reply
            .value32()
            .map(|values| values.collect())
            .unwrap_or_default())
    }

    fn atom(&self, name: &str) -> Result<Atom> {
        self.conn
            .intern_atom(false, name.as_bytes())
            .map_err(|err| msg(err.to_string()))?
            .reply()
            .map(|reply| reply.atom)
            .map_err(|err| msg(err.to_string()))
    }

    fn keymap(&mut self) -> Result<&Keymap> {
        if self.keymap.is_none() {
            let setup = self.conn.setup();
            let min = setup.min_keycode;
            let count = setup.max_keycode.saturating_sub(min).saturating_add(1);
            let reply = self
                .conn
                .get_keyboard_mapping(min, count)
                .map_err(|err| msg(err.to_string()))?
                .reply()
                .map_err(|err| msg(err.to_string()))?;
            self.keymap = Some(Keymap {
                min,
                per: reply.keysyms_per_keycode as usize,
                syms: reply.keysyms,
            });
        }
        Ok(self.keymap.as_ref().unwrap())
    }

    fn keycode_for(&mut self, keysym: u32) -> Result<(Keycode, bool)> {
        let map = self.keymap()?;
        let per = map.per.max(1);
        for (index, chunk) in map.syms.chunks(per).enumerate() {
            if chunk.first() == Some(&keysym) {
                return Ok((map.min.saturating_add(index as u8), false));
            }
            if chunk.get(1) == Some(&keysym) {
                return Ok((map.min.saturating_add(index as u8), true));
            }
        }
        Err(msg(format!("keysym {keysym:#x} is not on the X keymap")))
    }

    fn fake(&self, kind: u8, detail: u8, x: i16, y: i16, absolute: bool) -> Result<()> {
        let root = if absolute { self.root } else { 0 };
        self.conn
            .xtest_fake_input(kind, detail, 0, root, x, y, 0)
            .map_err(|err| msg(format!("XTest: {err}")))?
            .check()
            .map_err(|err| msg(format!("XTest: {err}")))?;
        Ok(())
    }

    fn tap_keysym(&mut self, keysym: u32) -> Result<()> {
        match self.keycode_for(keysym) {
            Ok((code, shift)) => {
                if shift {
                    let (shift_code, _) = self.keycode_for(0xffe1)?;
                    self.fake(KEY_PRESS, shift_code, 0, 0, false)?;
                    self.fake(KEY_PRESS, code, 0, 0, false)?;
                    self.fake(KEY_RELEASE, code, 0, 0, false)?;
                    self.fake(KEY_RELEASE, shift_code, 0, 0, false)?;
                } else {
                    self.fake(KEY_PRESS, code, 0, 0, false)?;
                    self.fake(KEY_RELEASE, code, 0, 0, false)?;
                }
                Ok(())
            }
            Err(_) => self.tap_temporary(keysym),
        }
    }

    fn tap_temporary(&mut self, keysym: u32) -> Result<()> {
        let setup = self.conn.setup();
        let code = setup.max_keycode.saturating_sub(1).max(setup.min_keycode);
        let previous = {
            let map = self.keymap()?;
            let per = map.per.max(1);
            let index = code.saturating_sub(map.min) as usize * per;
            map.syms.get(index).copied().unwrap_or(0)
        };
        self.conn
            .change_keyboard_mapping(1, code, 1, &[keysym])
            .map_err(|err| msg(err.to_string()))?
            .check()
            .map_err(|err| msg(format!("ChangeKeyboardMapping: {err}")))?;
        self.fake(KEY_PRESS, code, 0, 0, false)?;
        self.fake(KEY_RELEASE, code, 0, 0, false)?;
        if let Ok(cookie) = self.conn.change_keyboard_mapping(1, code, 1, &[previous]) {
            let _ = cookie.check();
        }
        // The cached map is stale for that keycode. Drop it.
        self.keymap = None;
        Ok(())
    }
}

impl Drop for X11Desk {
    fn drop(&mut self) {
        self.drop_shm();
    }
}

impl Pointer for X11Desk {
    fn mouse_move(&mut self, x: i32, y: i32) -> Result<()> {
        let x = i16::try_from(x).map_err(|_| msg("pointer x does not fit in i16"))?;
        let y = i16::try_from(y).map_err(|_| msg("pointer y does not fit in i16"))?;
        self.fake(MOTION_NOTIFY, 0, x, y, true)
    }

    fn mouse_button(&mut self, button: MouseButton, down: bool) -> Result<()> {
        let kind = if down { BUTTON_PRESS } else { BUTTON_RELEASE };
        self.fake(kind, button.xtest(), 0, 0, false)
    }

    fn scroll(&mut self, dx: i32, dy: i32) -> Result<()> {
        // `dx`/`dy` are notches (WHEEL_DELTA multiples). Each notch is one
        // XTest button click. Positive dy scrolls up (button 4); positive dx
        // scrolls right (button 7).
        click_scroll(self, dy, 4, 5)?;
        click_scroll(self, dx, 7, 6)?;
        Ok(())
    }

    fn key_down(&mut self, key: &str) -> Result<()> {
        let info = key_info(key).ok_or_else(|| msg(format!("unknown key '{key}'")))?;
        let (code, _) = self.keycode_for(info.keysym)?;
        self.fake(KEY_PRESS, code, 0, 0, false)
    }

    fn key_up(&mut self, key: &str) -> Result<()> {
        let info = key_info(key).ok_or_else(|| msg(format!("unknown key '{key}'")))?;
        let (code, _) = self.keycode_for(info.keysym)?;
        self.fake(KEY_RELEASE, code, 0, 0, false)
    }

    fn type_text(&mut self, text: &str) -> Result<()> {
        for ch in text.chars() {
            let keysym = match ch {
                '\n' => 0xff0d,
                '\t' => 0xff09,
                '\r' => continue,
                ch if (ch as u32) <= 0xff => ch as u32,
                ch => 0x0100_0000 + (ch as u32),
            };
            self.tap_keysym(keysym)?;
            std::thread::sleep(Duration::from_millis(4));
        }
        Ok(())
    }
}

fn click_scroll(desk: &mut X11Desk, amount: i32, positive: u8, negative: u8) -> Result<()> {
    let button = if amount > 0 { positive } else { negative };
    for _ in 0..amount.abs() {
        desk.fake(BUTTON_PRESS, button, 0, 0, false)?;
        desk.fake(BUTTON_RELEASE, button, 0, 0, false)?;
    }
    Ok(())
}

fn pack_ximage(
    data: &[u8],
    width: u32,
    height: u32,
    stride: u32,
    bpp: usize,
    lsb_first: bool,
    depth: u8,
    backend: &str,
) -> Result<Frame> {
    if bpp < 3 {
        return Err(msg(format!(
            "X11 depth {depth} uses {bpp} bytes per pixel; 24/32-bit TrueColor is required"
        )));
    }
    let mut bgra = vec![0u8; width as usize * height as usize * 4];
    for y in 0..height as usize {
        for x in 0..width as usize {
            let src = y * stride as usize + x * bpp;
            if src + 3 > data.len() && src + bpp > data.len() {
                continue;
            }
            let (b, g, r) = if lsb_first || bpp == 4 {
                // Little-endian 32-bit TrueColor is B, G, R, X on the usual Intel servers.
                let b = data.get(src).copied().unwrap_or(0);
                let g = data.get(src + 1).copied().unwrap_or(0);
                let r = data.get(src + 2).copied().unwrap_or(0);
                if lsb_first {
                    (b, g, r)
                } else {
                    // Big-endian 32-bit is typically X, R, G, B.
                    let r = data.get(src + 1).copied().unwrap_or(0);
                    let g = data.get(src + 2).copied().unwrap_or(0);
                    let b = data.get(src + 3).copied().unwrap_or(0);
                    (b, g, r)
                }
            } else {
                (
                    data.get(src).copied().unwrap_or(0),
                    data.get(src + 1).copied().unwrap_or(0),
                    data.get(src + 2).copied().unwrap_or(0),
                )
            };
            let dst = (y * width as usize + x) * 4;
            bgra[dst] = b;
            bgra[dst + 1] = g;
            bgra[dst + 2] = r;
            bgra[dst + 3] = 255;
        }
    }
    Frame::from_bgra(width, height, width * 4, &bgra, backend)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_when_display_is_set() {
        if std::env::var_os("DISPLAY")
            .filter(|value| !value.is_empty())
            .is_none()
        {
            return;
        }
        let mut desk = match X11Desk::connect() {
            Ok(desk) => desk,
            Err(err) => {
                eprintln!("skipping X11 capture: {err}");
                return;
            }
        };
        let frame = desk.capture_full().expect("X11 full capture");
        assert!(frame.width > 0 && frame.height > 0);
        assert_eq!(
            frame.pixels.len(),
            frame.width as usize * frame.height as usize * 4
        );
        assert!(frame.backend.starts_with("x11"));
        if std::env::var("AGENTLINK_X11_INPUT").ok().as_deref() == Some("1") {
            desk.mouse_move(1, 1).expect("XTest motion");
        }
    }
}
