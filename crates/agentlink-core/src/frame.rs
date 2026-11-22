//! Binary WebSocket frames for file bytes.
//!
//! Control messages stay JSON text frames. A file chunk is a binary frame
//! whose first bytes carry the request id, the file offset, and a compression
//! flag. The relay forwards the frame using only the request id.

use uuid::Uuid;

use crate::error::{Error, Result};

pub const FRAME_VERSION: u8 = 1;
pub const HEADER_LEN: usize = 40;
pub const KIND_DATA: u8 = 1;
pub const KIND_TAR: u8 = 2;
pub const FLAG_ZSTD: u16 = 1;
/// Payload is ChaCha20-Poly1305 ciphertext. The header stays in the clear so
/// the relay can route on the request id.
pub const FLAG_E2E: u16 = 2;
/// Empty payload; `raw_len` logical bytes are a filesystem hole (zeros).
pub const FLAG_HOLE: u16 = 4;

pub const DEFAULT_CHUNK: usize = 1024 * 1024;
pub const MIN_CHUNK: usize = 64 * 1024;
pub const MAX_CHUNK: usize = 4 * 1024 * 1024;
pub const DEFAULT_WINDOW: usize = 8;
pub const DEFAULT_PARALLEL: usize = 4;
/// Largest binary frame the WebSocket will accept (chunk plus header).
pub const MAX_FRAME: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataFrame {
    pub request_id: String,
    pub offset: u64,
    pub raw_len: u32,
    pub compressed: bool,
    /// When set the payload is empty and the receiver extends with zeros.
    pub hole: bool,
    pub tar: bool,
    pub payload: Vec<u8>,
}

pub fn clamp_chunk(size: usize) -> usize {
    size.clamp(MIN_CHUNK, MAX_CHUNK)
}

pub fn encode(frame: &DataFrame) -> Result<Vec<u8>> {
    let id = Uuid::parse_str(&frame.request_id)
        .map_err(|e| Error::Protocol(format!("request id: {e}")))?;
    let mut out = Vec::with_capacity(HEADER_LEN + frame.payload.len());
    out.push(FRAME_VERSION);
    out.push(if frame.tar { KIND_TAR } else { KIND_DATA });
    let mut flags = 0u16;
    if frame.compressed {
        flags |= FLAG_ZSTD;
    }
    if frame.hole {
        flags |= FLAG_HOLE;
    }
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&frame.offset.to_le_bytes());
    out.extend_from_slice(id.as_bytes());
    out.extend_from_slice(&frame.raw_len.to_le_bytes());
    let payload_len = u32::try_from(frame.payload.len())
        .map_err(|_| Error::Protocol("chunk too large".into()))?;
    out.extend_from_slice(&payload_len.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&frame.payload);
    Ok(out)
}

pub fn decode(bytes: &[u8]) -> Result<DataFrame> {
    if bytes.len() < HEADER_LEN {
        return Err(Error::Protocol("short binary frame".into()));
    }
    if bytes[0] != FRAME_VERSION {
        return Err(Error::Protocol(format!(
            "unsupported frame version {}",
            bytes[0]
        )));
    }
    let kind = bytes[1];
    if kind != KIND_DATA && kind != KIND_TAR {
        return Err(Error::Protocol(format!("unknown frame kind {kind}")));
    }
    if bytes.len() > MAX_FRAME {
        return Err(Error::Protocol("binary frame too large".into()));
    }
    let flags = u16::from_le_bytes([bytes[2], bytes[3]]);
    if flags & !(FLAG_ZSTD | FLAG_E2E | FLAG_HOLE) != 0 {
        return Err(Error::Protocol(format!(
            "unknown binary frame flags 0x{flags:04x}"
        )));
    }
    let offset = u64::from_le_bytes(bytes[4..12].try_into().unwrap());
    let mut id_bytes = [0u8; 16];
    id_bytes.copy_from_slice(&bytes[12..28]);
    let request_id = Uuid::from_bytes(id_bytes).to_string();
    let raw_len = u32::from_le_bytes(bytes[28..32].try_into().unwrap());
    let payload_len = u32::from_le_bytes(bytes[32..36].try_into().unwrap()) as usize;
    if bytes.len() != HEADER_LEN + payload_len {
        return Err(Error::Protocol("binary frame length mismatch".into()));
    }
    let compressed = flags & FLAG_ZSTD != 0;
    let hole = flags & FLAG_HOLE != 0;
    if hole {
        if compressed {
            return Err(Error::Protocol("hole frame cannot be compressed".into()));
        }
        if u64::from(raw_len) > crate::sparse::FILE_MAX_HOLE {
            return Err(Error::Protocol(format!(
                "hole frame raw_len {raw_len} exceeds {} byte cap",
                crate::sparse::FILE_MAX_HOLE
            )));
        }
        if flags & FLAG_E2E == 0 && payload_len != 0 {
            return Err(Error::Protocol(
                "hole frame must have empty payload".into(),
            ));
        }
    }
    Ok(DataFrame {
        request_id,
        offset,
        raw_len,
        compressed,
        hole,
        tar: kind == KIND_TAR,
        payload: bytes[HEADER_LEN..].to_vec(),
    })
}

/// Raw header fields bound into E2E frame AAD v2:
/// `(version, kind, non_e2e_flags, offset, raw_len, request_id)`.
pub fn header_fields(bytes: &[u8]) -> Result<(u8, u8, u16, u64, u32, String)> {
    if bytes.len() < HEADER_LEN {
        return Err(Error::Protocol("short binary frame".into()));
    }
    let version = bytes[0];
    let kind = bytes[1];
    let flags = u16::from_le_bytes([bytes[2], bytes[3]]);
    let non_e2e_flags = flags & !FLAG_E2E;
    let offset = u64::from_le_bytes(bytes[4..12].try_into().unwrap());
    let mut id_bytes = [0u8; 16];
    id_bytes.copy_from_slice(&bytes[12..28]);
    let request_id = Uuid::from_bytes(id_bytes).to_string();
    let raw_len = u32::from_le_bytes(bytes[28..32].try_into().unwrap());
    Ok((version, kind, non_e2e_flags, offset, raw_len, request_id))
}

/// `true` when the frame header carries [`FLAG_E2E`].
///
/// Short buffers and frames with a different version are `false`.
pub fn is_e2e(bytes: &[u8]) -> bool {
    if bytes.len() < 4 || bytes[0] != FRAME_VERSION {
        return false;
    }
    let flags = u16::from_le_bytes([bytes[2], bytes[3]]);
    flags & FLAG_E2E != 0
}

/// Rebuild a frame with a new payload. `e2e` sets or clears [`FLAG_E2E`].
pub fn replace_payload(bytes: &[u8], payload: &[u8], e2e: bool) -> Result<Vec<u8>> {
    let mut frame = decode(bytes)?;
    frame.payload = payload.to_vec();
    let mut out = encode(&frame)?;
    let mut flags = u16::from_le_bytes([out[2], out[3]]);
    if e2e {
        flags |= FLAG_E2E;
    } else {
        flags &= !FLAG_E2E;
    }
    out[2..4].copy_from_slice(&flags.to_le_bytes());
    Ok(out)
}

/// Request id for relay routing. `None` when the frame is too short or the
/// version is not one of ours; the caller ignores it.
pub fn request_id(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 28 || bytes[0] != FRAME_VERSION {
        return None;
    }
    let mut id_bytes = [0u8; 16];
    id_bytes.copy_from_slice(&bytes[12..28]);
    Some(Uuid::from_bytes(id_bytes).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_request_id() {
        let frame = DataFrame {
            request_id: Uuid::new_v4().to_string(),
            offset: 4_194_304,
            raw_len: 3,
            compressed: true,
            hole: false,
            tar: false,
            payload: vec![1, 2, 3, 4],
        };
        let bytes = encode(&frame).unwrap();
        assert_eq!(
            request_id(&bytes).as_deref(),
            Some(frame.request_id.as_str())
        );
        let back = decode(&bytes).unwrap();
        assert_eq!(back, frame);
    }

    #[test]
    fn hole_frame_roundtrip() {
        let frame = DataFrame {
            request_id: Uuid::new_v4().to_string(),
            offset: 1_048_576,
            raw_len: 8_388_608,
            compressed: false,
            hole: true,
            tar: false,
            payload: vec![],
        };
        let bytes = encode(&frame).unwrap();
        assert_eq!(bytes.len(), HEADER_LEN);
        let back = decode(&bytes).unwrap();
        assert_eq!(back, frame);
        assert!(back.hole);
    }
}
