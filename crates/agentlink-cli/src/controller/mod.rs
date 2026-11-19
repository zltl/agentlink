//! Desktop controller for Windows and glibc Linux.
//!
//! Musl release binaries stay headless. `agentlink controller` on those builds
//! explains how to compile the window.

mod autostart;
#[cfg(not(target_env = "musl"))]
mod diagnostics;
/// STD-only ordered input reducer (also `rustc --test` without workspace deps).
#[cfg(not(target_env = "musl"))]
mod input_policy;
mod model;

#[cfg(not(target_env = "musl"))]
mod chrome;
#[cfg(all(unix, not(target_env = "musl")))]
mod debug;
#[cfg(not(target_env = "musl"))]
mod decode;
#[cfg(not(target_env = "musl"))]
mod fonts;
#[cfg(not(target_env = "musl"))]
mod indicator;
#[cfg(not(target_env = "musl"))]
mod term;
#[cfg(not(target_env = "musl"))]
mod term_local_echo;
mod theme;
#[cfg(not(target_env = "musl"))]
mod field_pad;
#[cfg(not(target_env = "musl"))]
mod desk_keys;
#[cfg(not(target_env = "musl"))]
mod input_adapter;
#[cfg(not(target_env = "musl"))]
mod ordered_send;
#[cfg(not(target_env = "musl"))]
mod ui;
#[cfg(not(target_env = "musl"))]
mod viewport;
#[cfg(not(target_env = "musl"))]
mod worker;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Fixture status line. Preview must not replace this with a live `load_view`.
pub const PREVIEW_NODE_LINE: &str = "This computer is not used in preview.";

/// Call counts for live side effects that preview must never trigger.
#[derive(Default)]
pub struct LiveCounters {
    pub resolve_data_dir: AtomicUsize,
    pub start_on_login: AtomicUsize,
    pub load_view: AtomicUsize,
}

/// Injectable production side effects (data-dir resolve, autostart, tray view).
#[derive(Clone)]
pub struct LiveHooks {
    pub counters: Arc<LiveCounters>,
    resolve_data_dir: fn(Option<&Path>) -> Result<PathBuf, String>,
    start_on_login: fn() -> bool,
    load_view: fn(&Path, &Path) -> crate::tray::StatusView,
}

impl Default for LiveHooks {
    fn default() -> Self {
        Self::production()
    }
}

impl LiveHooks {
    pub fn production() -> Self {
        Self {
            counters: Arc::new(LiveCounters::default()),
            resolve_data_dir: production_resolve_data_dir,
            start_on_login: production_start_on_login,
            load_view: crate::tray::load_view,
        }
    }

    /// Test hooks that never read or write production autostart / HKCU / data-dir.
    pub fn inert_for_tests() -> Self {
        Self {
            counters: Arc::new(LiveCounters::default()),
            resolve_data_dir: inert_resolve_data_dir,
            start_on_login: inert_start_on_login,
            load_view: inert_load_view,
        }
    }

    pub fn resolve_data_dir(&self, explicit: Option<&Path>) -> Result<PathBuf, String> {
        self.counters
            .resolve_data_dir
            .fetch_add(1, Ordering::SeqCst);
        (self.resolve_data_dir)(explicit)
    }

    pub fn start_on_login(&self) -> bool {
        self.counters.start_on_login.fetch_add(1, Ordering::SeqCst);
        (self.start_on_login)()
    }

    pub fn load_view(&self, data_dir: &Path, config_dir: &Path) -> crate::tray::StatusView {
        self.counters.load_view.fetch_add(1, Ordering::SeqCst);
        (self.load_view)(data_dir, config_dir)
    }

    pub fn counts(&self) -> (usize, usize, usize) {
        (
            self.counters.resolve_data_dir.load(Ordering::SeqCst),
            self.counters.start_on_login.load(Ordering::SeqCst),
            self.counters.load_view.load(Ordering::SeqCst),
        )
    }
}

fn production_resolve_data_dir(explicit: Option<&Path>) -> Result<PathBuf, String> {
    crate::tray::resolve_data_dir(explicit).map_err(|err| err.to_string())
}

fn production_start_on_login() -> bool {
    #[cfg(windows)]
    {
        crate::tray::autostart_enabled()
    }
    #[cfg(not(windows))]
    {
        autostart::enabled()
    }
}

fn inert_resolve_data_dir(_explicit: Option<&Path>) -> Result<PathBuf, String> {
    Err("test inert: production data-dir resolve disabled".into())
}

fn inert_start_on_login() -> bool {
    false
}

fn inert_load_view(_data_dir: &Path, _config_dir: &Path) -> crate::tray::StatusView {
    crate::tray::StatusView {
        connection: "Stopped".into(),
        relay: String::new(),
        node_name: String::new(),
        pairing: "off".into(),
        account: "test".into(),
        detail: String::new(),
        running: false,
        enrolled: false,
    }
}

/// Persistent isolated preview root. Not a RAII temp; it is left in place
/// when the process exits (no-delete includes tmp).
pub fn isolated_preview_root() -> PathBuf {
    std::env::temp_dir().join(format!("agentlink-preview-ui-{}", std::process::id()))
}

/// Isolated config/data directories for `--preview-ui`.
///
/// Does not resolve the caller's default data or config dir and does not
/// read start-on-login or a tray view. `live` is accepted so tests can
/// prove those hooks stay at zero.
pub fn enter_preview_setup(_live: &LiveHooks) -> PreviewDirs {
    let root = isolated_preview_root();
    let config_dir = root.join("config");
    let data_dir = root.join("data");
    let _ = std::fs::create_dir_all(&config_dir);
    let _ = std::fs::create_dir_all(&data_dir);
    PreviewDirs {
        root,
        config_dir,
        data_dir,
    }
}

pub struct PreviewDirs {
    pub root: PathBuf,
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
}

/// Isolated preview entry. Never resolves real data/config paths, never
/// starts the tray, worker, or auto-start, and never reads a live account.
pub fn enter_preview() -> i32 {
    #[cfg(not(target_env = "musl"))]
    {
        let dirs = enter_preview_setup(&LiveHooks::production());
        return ui::enter_with_opts(ui::EnterOpts {
            config_dir: dirs.config_dir,
            data_dir: dirs.data_dir,
            tray: false,
            background: false,
            mock: true,
            headless: false,
            fail_connect: false,
            connect_timeout_secs: 12,
            max_fps: 30,
            perf_log: None,
            debug_inbox: None,
            logical_size: (1080.0, 760.0),
            open_desktop: None,
            preview_ui: true,
        });
    }
    #[cfg(target_env = "musl")]
    {
        eprintln!(
            "this build has no desktop window. On Linux, build the glibc binary: cargo build -p agentlink-cli"
        );
        1
    }
}

pub fn available() -> bool {
    cfg!(not(target_env = "musl"))
}

pub struct EnterArgs {
    pub config_dir: std::path::PathBuf,
    pub data_dir: Option<std::path::PathBuf>,
    pub tray: bool,
    pub background: bool,
    pub check: bool,
    pub debug_socket: Option<std::path::PathBuf>,
    pub mock: bool,
    pub headless: bool,
    pub fail_connect: bool,
    pub connect_timeout_secs: u64,
    pub max_fps: u32,
    pub perf_log: Option<std::path::PathBuf>,
    /// Open this node's desktop once the machine list arrives.
    pub open_desktop: Option<String>,
    /// Isolated layout fixture. Temporary dirs, no live account, no auto-start.
    pub preview_ui: bool,
}

pub fn enter(
    config_dir: std::path::PathBuf,
    data_dir: Option<std::path::PathBuf>,
    tray: bool,
    background: bool,
    check: bool,
) -> i32 {
    enter_args(EnterArgs {
        config_dir,
        data_dir,
        tray,
        background,
        check,
        debug_socket: None,
        mock: false,
        headless: false,
        fail_connect: false,
        connect_timeout_secs: 12,
        max_fps: 30,
        perf_log: None,
        open_desktop: None,
        preview_ui: false,
    })
}

pub fn enter_args(args: EnterArgs) -> i32 {
    if args.check {
        if available() {
            println!("controller: ready");
            return 0;
        }
        println!("controller: unavailable");
        eprintln!(
            "this build has no desktop window. On Linux, build the glibc binary: cargo build -p agentlink-cli"
        );
        return 1;
    }
    if args.preview_ui {
        // Isolated entry: no default data/config resolve, no live flags.
        return enter_preview();
    }
    #[cfg(not(target_env = "musl"))]
    {
        let data_dir = match args.data_dir {
            Some(path) => path,
            None => match crate::tray::resolve_data_dir(None) {
                Ok(path) => path,
                Err(err) => {
                    eprintln!("{err}");
                    return 1;
                }
            },
        };
        #[cfg(unix)]
        if let Some(socket) = args.debug_socket {
            return debug::enter_debug(
                args.config_dir,
                data_dir,
                args.tray,
                args.background,
                debug::DebugOpts {
                    socket,
                    mock: args.mock,
                    headless: args.headless,
                    fail_connect: args.fail_connect,
                    connect_timeout_secs: args.connect_timeout_secs,
                    max_fps: args.max_fps,
                    perf_log: args.perf_log.clone(),
                },
            );
        }
        #[cfg(not(unix))]
        if args.debug_socket.is_some() || args.headless {
            eprintln!("controller debug socket requires unix");
            return 1;
        }
        if args.headless {
            eprintln!("controller --headless requires --debug-socket");
            return 1;
        }
        if args.mock {
            return ui::enter_with_opts(ui::EnterOpts {
                config_dir: args.config_dir,
                data_dir,
                tray: args.tray,
                background: args.background,
                mock: true,
                headless: false,
                fail_connect: args.fail_connect,
                connect_timeout_secs: args.connect_timeout_secs,
                max_fps: args.max_fps,
                perf_log: args.perf_log,
                debug_inbox: None,
                logical_size: (1440.0, 900.0),
                open_desktop: args.open_desktop.clone(),
                preview_ui: false,
            });
        }
        return ui::enter_with_opts(ui::EnterOpts {
            config_dir: args.config_dir,
            data_dir,
            tray: args.tray,
            background: args.background,
            mock: false,
            headless: false,
            fail_connect: false,
            connect_timeout_secs: args.connect_timeout_secs,
            max_fps: args.max_fps,
            perf_log: args.perf_log,
            debug_inbox: None,
            logical_size: (1080.0, 760.0),
            open_desktop: args.open_desktop.clone(),
            preview_ui: false,
        });
    }
    #[cfg(target_env = "musl")]
    {
        let _ = args;
        eprintln!(
            "this build has no desktop window. On Linux, build the glibc binary: cargo build -p agentlink-cli"
        );
        1
    }
}

#[cfg(test)]
mod preview_isolation_tests {
    use super::*;

    #[test]
    fn enter_preview_setup_skips_live_hooks() {
        let live = LiveHooks::production();
        let dirs = enter_preview_setup(&live);
        assert_eq!(live.counts(), (0, 0, 0));
        assert!(dirs.config_dir.ends_with("config"));
        assert!(dirs.data_dir.ends_with("data"));
        assert!(dirs.config_dir.starts_with(isolated_preview_root()));
        assert!(dirs.config_dir.is_dir());
        assert!(dirs.data_dir.is_dir());
        // Isolation keeps the temp tree; this test must not delete it.
        assert!(isolated_preview_root().starts_with(std::env::temp_dir()));
    }

    #[test]
    fn inert_hooks_never_touch_production_autostart() {
        let live = LiveHooks::inert_for_tests();
        assert!(!live.start_on_login());
        assert_eq!(live.counts(), (0, 1, 0));
        let err = live
            .resolve_data_dir(None)
            .expect_err("inert must not resolve production data-dir");
        assert!(err.contains("inert"));
        let view = live.load_view(Path::new("/nope"), Path::new("/nope"));
        assert!(!view.running);
        assert_eq!(live.counts(), (1, 1, 1));
    }
}
