//! BLAKE3 file hashes and an rsync-style block delta.
//!
//! The receiver publishes a weak rolling checksum and a BLAKE3 prefix for each
//! fixed block. The sender scans with the rolling checksum and emits copy
//! operations for matches plus literal spans for the bytes that changed.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::error::Result;
use crate::protocol::{BlockSig, ByteRange, PlanOp, SigTable};
use crate::sparse;

pub const DELTA_MIN_SIZE: u64 = 128 * 1024;
pub const DEFAULT_BLOCK: usize = 64 * 1024;

const MOD: u32 = 65521;

pub fn hash_bytes(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

/// Reused zero slab so hole hashing never allocates or touches the disk.
const ZERO_SLAB: [u8; 1024 * 1024] = [0u8; 1024 * 1024];

fn update_zeros(hasher: &mut blake3::Hasher, mut len: u64) {
    while len > 0 {
        let n = usize::try_from(len.min(ZERO_SLAB.len() as u64)).unwrap_or(ZERO_SLAB.len());
        hasher.update(&ZERO_SLAB[..n]);
        len -= n as u64;
    }
}

/// BLAKE3 of the file's logical bytes.
///
/// On unix, filesystem holes (`SEEK_DATA` / `SEEK_HOLE`) are hashed as zeros
/// without reading them, so a sparse multi-GiB file is cheap to fingerprint.
/// Dense files and platforms without seek-hole fall back to a full read.
pub fn hash_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let size = file.metadata()?.len();
    if size == 0 {
        return Ok(hash_bytes(b""));
    }
    if let Ok(pieces) = sparse::partition(
        path,
        &[ByteRange {
            start: 0,
            end: size,
        }],
    ) {
        if pieces.iter().any(|p| p.hole) {
            let mut hasher = blake3::Hasher::new();
            let mut buf = vec![0u8; 1024 * 1024];
            for piece in pieces {
                if piece.len() == 0 {
                    continue;
                }
                if piece.hole {
                    update_zeros(&mut hasher, piece.len());
                    continue;
                }
                file.seek(SeekFrom::Start(piece.start))?;
                let mut left = piece.len();
                while left > 0 {
                    let want = usize::try_from(left.min(buf.len() as u64)).unwrap_or(buf.len());
                    let n = file.read(&mut buf[..want])?;
                    if n == 0 {
                        // Unexpected EOF inside a data extent — treat remainder as zeros.
                        update_zeros(&mut hasher, left);
                        break;
                    }
                    hasher.update(&buf[..n]);
                    left -= n as u64;
                }
            }
            return Ok(hasher.finalize().to_hex().to_string());
        }
    }
    // Dense / unsupported: stream the whole file.
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

pub fn strong16(data: &[u8]) -> String {
    let hash = blake3::hash(data);
    hex::encode(&hash.as_bytes()[..16])
}

pub fn adler32(data: &[u8]) -> u32 {
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a += byte as u32;
        if a >= MOD {
            a -= MOD;
        }
        b += a;
        if b >= MOD {
            b -= MOD;
        }
    }
    (b << 16) | a
}

/// Roll a window of `window` bytes: drop `outgoing`, append `incoming`.
pub fn roll_adler(sum: u32, window: usize, outgoing: u8, incoming: u8) -> u32 {
    let a = sum & 0xffff;
    let b = sum >> 16;
    let a2 = (a + MOD - u32::from(outgoing) + u32::from(incoming)) % MOD;
    // `window` is the remote block size. Multiply in u64: `n * outgoing` overflows
    // a u32 (and panics in debug) once the block is larger than about 16 MiB.
    // Only `window % MOD` affects the checksum.
    let n = (window as u64) % u64::from(MOD);
    let sub = ((n * u64::from(outgoing)) % u64::from(MOD)) as u32;
    let b2 = (b + MOD * 2 - sub + a2 + MOD - 1) % MOD;
    (b2 << 16) | a2
}

pub fn signatures(data: &[u8], block: usize) -> SigTable {
    let block = block.max(1);
    let mut sigs = Vec::new();
    let mut off = 0usize;
    while off + block <= data.len() {
        let chunk = &data[off..off + block];
        sigs.push(BlockSig {
            off: off as u64,
            len: block as u32,
            weak: adler32(chunk),
            strong: strong16(chunk),
        });
        off += block;
    }
    SigTable {
        block: block as u32,
        sigs,
    }
}

pub fn signatures_file(path: &Path, block: usize) -> Result<SigTable> {
    let mut file = File::open(path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    Ok(signatures(&data, block))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub ops: Vec<PlanOp>,
    pub literal_bytes: u64,
    pub copy_bytes: u64,
}

pub fn plan(new_data: &[u8], table: &SigTable) -> Plan {
    let block = table.block.max(1) as usize;
    let mut index: HashMap<u32, Vec<&BlockSig>> = HashMap::new();
    for sig in &table.sigs {
        index.entry(sig.weak).or_default().push(sig);
    }

    let mut ops = Vec::new();
    let mut literal_at: Option<u64> = None;
    let mut literal_len = 0u64;
    let mut copy_bytes = 0u64;
    let flush_lit = |ops: &mut Vec<PlanOp>, at: &mut Option<u64>, len: &mut u64| {
        if let Some(new) = at.take() {
            if *len > 0 {
                ops.push(PlanOp::Lit { new, len: *len });
            }
            *len = 0;
        }
    };

    if new_data.len() < block || table.sigs.is_empty() {
        return Plan {
            ops: vec![PlanOp::Lit {
                new: 0,
                len: new_data.len() as u64,
            }],
            literal_bytes: new_data.len() as u64,
            copy_bytes: 0,
        };
    }

    let mut i = 0usize;
    let mut weak = adler32(&new_data[..block]);
    while i + block <= new_data.len() {
        let mut matched = None;
        if let Some(cands) = index.get(&weak) {
            let strong = strong16(&new_data[i..i + block]);
            for sig in cands {
                if sig.strong == strong && sig.len as usize == block {
                    matched = Some(*sig);
                    break;
                }
            }
        }
        if let Some(sig) = matched {
            flush_lit(&mut ops, &mut literal_at, &mut literal_len);
            ops.push(PlanOp::Copy {
                old: sig.off,
                new: i as u64,
                len: block as u64,
            });
            copy_bytes += block as u64;
            i += block;
            if i + block <= new_data.len() {
                weak = adler32(&new_data[i..i + block]);
            }
        } else {
            if literal_at.is_none() {
                literal_at = Some(i as u64);
            }
            literal_len += 1;
            let next = i + 1;
            if next + block <= new_data.len() {
                weak = roll_adler(weak, block, new_data[i], new_data[next + block - 1]);
            }
            i = next;
        }
    }
    if i < new_data.len() {
        if literal_at.is_none() {
            literal_at = Some(i as u64);
        }
        literal_len += (new_data.len() - i) as u64;
    }
    flush_lit(&mut ops, &mut literal_at, &mut literal_len);
    let literal_bytes = new_data.len() as u64 - copy_bytes;
    Plan {
        ops,
        literal_bytes,
        copy_bytes,
    }
}

pub fn plan_worth(plan: &Plan, size: u64) -> bool {
    size > 0 && plan.literal_bytes + 4096 < size * 8 / 10 && plan.copy_bytes > 0
}

pub fn merge_ranges(mut ranges: Vec<ByteRange>) -> Vec<ByteRange> {
    ranges.retain(|r| r.end > r.start);
    ranges.sort_by_key(|r| r.start);
    let mut out: Vec<ByteRange> = Vec::new();
    for range in ranges {
        if let Some(last) = out.last_mut() {
            if range.start <= last.end {
                last.end = last.end.max(range.end);
                continue;
            }
        }
        out.push(range);
    }
    out
}

pub fn missing_ranges(size: u64, have: &[ByteRange]) -> Vec<ByteRange> {
    let have = merge_ranges(have.to_vec());
    let mut missing = Vec::new();
    let mut cursor = 0u64;
    for range in have {
        if range.start > cursor {
            missing.push(ByteRange {
                start: cursor,
                end: range.start.min(size),
            });
        }
        cursor = cursor.max(range.end);
        if cursor >= size {
            break;
        }
    }
    if cursor < size {
        missing.push(ByteRange {
            start: cursor,
            end: size,
        });
    }
    missing.retain(|r| r.end > r.start);
    missing
}

pub fn range_covers(ranges: &[ByteRange], start: u64, end: u64) -> bool {
    ranges.iter().any(|r| r.start <= start && r.end >= end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roll_adler_large_window_matches_modular_formula() {
        let sum = adler32(&[7u8; 64]);
        let window = 50_000_000usize;
        let rolled = roll_adler(sum, window, 7, 9);
        let n = (window as u64) % u64::from(MOD);
        let a = sum & 0xffff;
        let b = sum >> 16;
        let a2 = (a + MOD - 7 + 9) % MOD;
        let sub = ((n * 7) % u64::from(MOD)) as u32;
        let b2 = (b + MOD * 2 - sub + a2 + MOD - 1) % MOD;
        assert_eq!(rolled, (b2 << 16) | a2);
    }

    #[test]
    fn rolling_checksum_matches_fresh_adler() {
        let data: Vec<u8> = (0..200u16).map(|n| (n * 17) as u8).collect();
        let window = 16;
        let mut weak = adler32(&data[..window]);
        for i in 0..data.len() - window {
            assert_eq!(weak, adler32(&data[i..i + window]), "at {i}");
            weak = roll_adler(weak, window, data[i], data[i + window]);
        }
    }

    #[test]
    fn delta_sends_only_the_changed_region() {
        let mut old = vec![7u8; 200_000];
        for (i, byte) in old.iter_mut().enumerate() {
            *byte = (i % 251) as u8;
        }
        let mut new = old.clone();
        for byte in &mut new[80_000..80_040] {
            *byte ^= 0xff;
        }
        let table = signatures(&old, 8_192);
        let plan = plan(&new, &table);
        assert!(plan_worth(&plan, new.len() as u64), "{plan:?}");
        assert!(plan.literal_bytes < 20_000, "{}", plan.literal_bytes);
        assert!(plan.copy_bytes > 180_000);
    }

    #[test]
    fn missing_ranges_fill_holes() {
        let have = vec![
            ByteRange { start: 0, end: 10 },
            ByteRange { start: 8, end: 20 },
            ByteRange { start: 30, end: 40 },
        ];
        assert_eq!(
            missing_ranges(50, &have),
            vec![
                ByteRange { start: 20, end: 30 },
                ByteRange { start: 40, end: 50 },
            ]
        );
    }

    #[test]
    fn sparse_file_hash_matches_dense_zeros() {
        use std::io::{Seek, SeekFrom, Write};
        let dir = tempfile::tempdir().unwrap();
        let sparse = dir.path().join("sparse.bin");
        let dense = dir.path().join("dense.bin");
        let mut f = File::create(&sparse).unwrap();
        f.seek(SeekFrom::Start(2 * 1024 * 1024)).unwrap();
        f.write_all(b"DATA").unwrap();
        f.set_len(4 * 1024 * 1024).unwrap();
        // Rewrite data after truncate (some FS clear extents on set_len).
        f.seek(SeekFrom::Start(2 * 1024 * 1024)).unwrap();
        f.write_all(b"DATA").unwrap();
        drop(f);

        let mut zeros = vec![0u8; 4 * 1024 * 1024];
        zeros[2 * 1024 * 1024..2 * 1024 * 1024 + 4].copy_from_slice(b"DATA");
        std::fs::write(&dense, &zeros).unwrap();

        let hs = hash_file(&sparse).unwrap();
        let hd = hash_file(&dense).unwrap();
        assert_eq!(hs, hd);
        assert_eq!(hs, hash_bytes(&zeros));
    }

    #[test]
    fn empty_file_hash_is_blake3_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty");
        std::fs::write(&path, b"").unwrap();
        assert_eq!(hash_file(&path).unwrap(), hash_bytes(b""));
    }
}

#[cfg(test)]
mod sparse_hash_bench {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};
    use std::time::Instant;

    #[test]
    fn sparse_64mib_hash_is_much_faster_than_dense_read_path() {
        let dir = tempfile::tempdir().unwrap();
        let sparse = dir.path().join("s.bin");
        let mut f = File::create(&sparse).unwrap();
        f.seek(SeekFrom::Start(32 * 1024 * 1024)).unwrap();
        f.write_all(b"X").unwrap();
        f.set_len(64 * 1024 * 1024).unwrap();
        f.seek(SeekFrom::Start(32 * 1024 * 1024)).unwrap();
        f.write_all(b"X").unwrap();
        drop(f);

        let t0 = Instant::now();
        let hs = hash_file(&sparse).unwrap();
        let sparse_ms = t0.elapsed().as_millis();

        // Force dense path by hashing a dense zero file of same logical layout size
        // for comparison of CPU; also time reading sparse the old way inline.
        let t1 = Instant::now();
        let mut file = File::open(&sparse).unwrap();
        let mut hasher = blake3::Hasher::new();
        let mut buf = vec![0u8; 1024 * 1024];
        loop {
            let n = std::io::Read::read(&mut file, &mut buf).unwrap();
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let naive = hasher.finalize().to_hex().to_string();
        let naive_ms = t1.elapsed().as_millis();

        assert_eq!(hs, naive);
        eprintln!("sparse_hash_ms={sparse_ms} naive_read_hash_ms={naive_ms}");
        // On a typical box sparse should be several times faster; keep a soft bound.
        assert!(
            sparse_ms * 2 < naive_ms || sparse_ms < 50,
            "sparse={sparse_ms}ms naive={naive_ms}ms"
        );
    }
}
