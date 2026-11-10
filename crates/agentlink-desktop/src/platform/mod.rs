//! Operating-system backends. Each one is created on the desktop worker thread.

use std::sync::Arc;

use crate::Desktop;

#[cfg(target_os = "linux")]
mod atspi;
#[cfg(target_os = "linux")]
mod ime;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(all(target_os = "linux", pipewire_headers))]
mod mutter;
#[cfg(target_os = "linux")]
mod portal_window;
#[cfg(target_os = "linux")]
mod shell_windows;
#[cfg(target_os = "linux")]
mod wayland;
#[cfg(target_os = "linux")]
mod x11;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
mod sck;
#[cfg(target_os = "windows")]
mod windows;

pub fn open() -> Arc<Desktop> {
    #[cfg(target_os = "linux")]
    {
        return linux::open();
    }
    #[cfg(target_os = "windows")]
    {
        return windows::open();
    }
    #[cfg(target_os = "macos")]
    {
        return macos::open();
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        tracing::warn!("this OS has no desktop backend; using the mock desktop");
        Desktop::mock()
    }
}
