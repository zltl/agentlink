//! Optional desktop audio as G.711 µ-law (PCMU), which browsers decode
//! without an extra codec library. Capture shells out to PipeWire or Pulse
//! when those tools exist. A missing tool leaves the session video-only.

use std::io::Read;
use std::process::{Child, Stdio};

use agentlink_core::process;

pub struct AudioCapture {
    child: Child,
}

impl AudioCapture {
    pub fn start() -> Option<Self> {
        let child = spawn_monitor()?;
        Some(Self { child })
    }

    pub fn read_pcm(&mut self, samples: &mut [i16]) -> Option<usize> {
        let stdout = self.child.stdout.as_mut()?;
        let mut raw = vec![0u8; samples.len() * 2];
        let mut filled = 0;
        while filled < raw.len() {
            match stdout.read(&mut raw[filled..]) {
                Ok(0) | Err(_) => return None,
                Ok(n) => filled += n,
            }
        }
        for (index, sample) in samples.iter_mut().enumerate() {
            let offset = index * 2;
            *sample = i16::from_le_bytes([raw[offset], raw[offset + 1]]);
        }
        Some(samples.len())
    }
}

impl Drop for AudioCapture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_monitor() -> Option<Child> {
    if let Some(child) = try_command(
        "pw-record",
        &[
            "--raw",
            "--format",
            "s16",
            "--rate",
            "8000",
            "--channels",
            "1",
            "-",
        ],
    ) {
        return Some(child);
    }
    try_command(
        "parecord",
        &[
            "--raw",
            "--format=s16le",
            "--rate=8000",
            "--channels=1",
            "--device=@DEFAULT_MONITOR@",
        ],
    )
}

fn try_command(program: &str, args: &[&str]) -> Option<Child> {
    process::hidden(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()
}

pub fn ulaw(sample: i16) -> u8 {
    let mut value = sample as i32;
    let sign = if value < 0 {
        value = -value;
        0x80
    } else {
        0
    };
    if value > 32635 {
        value = 32635;
    }
    value += 0x84;
    let mut exponent = 7i32;
    let mut mask = 0x4000;
    while exponent > 0 && (value & mask) == 0 {
        exponent -= 1;
        mask >>= 1;
    }
    let mantissa = (value >> (exponent + 3)) & 0x0f;
    !(sign | (exponent << 4) | mantissa) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn silence_is_ulaw_ff() {
        assert_eq!(ulaw(0), 0xff);
    }
}
