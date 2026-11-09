//! In-process hardware encoders.
//!
//! macOS uses VideoToolbox. Windows uses a Media Foundation hardware MFT,
//! which is how NVENC, Intel Quick Sync, and AMD AMF show up on that OS.
//! Linux NVENC / VAAPI / QSV are selected in the ffmpeg backend when those
//! encoder names exist; this module only probes the libraries so the log
//! says why a direct session was not opened.

use super::encode::{EncoderRequest, VideoEncoder};

pub fn try_hardware(request: &EncoderRequest) -> Option<Box<dyn VideoEncoder>> {
    #[cfg(target_os = "macos")]
    {
        if let Some(encoder) = super::videotoolbox::try_open(request) {
            return Some(encoder);
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(encoder) = super::media_foundation::try_open(request) {
            return Some(encoder);
        }
    }
    #[cfg(target_os = "linux")]
    {
        probe_linux();
    }
    let _ = request;
    None
}

#[cfg(target_os = "linux")]
fn probe_linux() {
    let nvenc = std::path::Path::new("/usr/lib/x86_64-linux-gnu/libnvidia-encode.so.1").exists()
        || std::path::Path::new("/usr/lib64/libnvidia-encode.so.1").exists()
        || libloading_probe("libnvidia-encode.so.1");
    let render = super::ffmpeg::find_render_node();
    if nvenc {
        tracing::debug!("NVENC library is present; ffmpeg h264_nvenc is the encode path");
    }
    if let Some(node) = render.as_deref() {
        // Trigger the one-shot VAAPI probe so the first session does not pay
        // for it under the viewer's offer deadline.
        let status = super::ffmpeg::vaapi_probe_status();
        match status {
            Some((mode, path)) => tracing::info!(
                render = %path,
                ?mode,
                "VAAPI h264 is available; ffmpeg h264_vaapi is the encode path"
            ),
            None => {
                let reason = super::ffmpeg::vaapi_probe_failure_reason()
                    .unwrap_or_else(|| format!("render node {node} present but probe failed"));
                tracing::warn!(
                    render = %node,
                    reason = %reason,
                    "VAAPI probe failed; sessions will use software encode"
                );
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn libloading_probe(name: &str) -> bool {
    unsafe { libloading::Library::new(name).is_ok() }
}
