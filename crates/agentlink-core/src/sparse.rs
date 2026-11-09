//! Partition file byte ranges into data vs holes.
//!
//! - Unix: `SEEK_DATA` / `SEEK_HOLE`
//! - Windows: `FSCTL_QUERY_ALLOCATED_RANGES`
//!
//! Used by the transfer sender (and sparse `hash_file`) so sparse files do
//! not burn CPU or wire on logical zeros. Unsupported filesystems fall back
//! to treating every range as data.

#![allow(unsafe_code)] // SEEK_DATA/SEEK_HOLE (unix) + FSCTL sparse (windows)

use std::fs::File;
use std::io;
use std::path::Path;

use crate::protocol::ByteRange;

/// One contiguous region inside a requested transfer range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Piece {
    pub start: u64,
    pub end: u64,
    /// When true the bytes are a filesystem hole (logical zeros); the sender
    /// may emit a hole frame instead of reading the file.
    pub hole: bool,
}

impl Piece {
    pub fn len(self) -> u64 {
        self.end.saturating_sub(self.start)
    }
}

/// Split `ranges` into data and hole pieces for `path`.
///
/// Pieces are ordered and cover exactly the union of `ranges` (clipped to the
/// file size is the caller's job). On failure to probe, every range becomes a
/// single data piece so behavior matches the pre-sparse sender.
pub fn partition(path: &Path, ranges: &[ByteRange]) -> io::Result<Vec<Piece>> {
    if ranges.is_empty() {
        return Ok(Vec::new());
    }
    #[cfg(unix)]
    {
        match partition_unix(path, ranges) {
            Ok(pieces) => Ok(pieces),
            Err(err) => {
                // ENOTSUP / EINVAL → filesystem has no SEEK_DATA. Fall back.
                if err.raw_os_error() == Some(libc::EINVAL)
                    || err.raw_os_error() == Some(libc::ENOTSUP)
                {
                    return Ok(ranges_as_data(ranges));
                }
                Err(err)
            }
        }
    }
    #[cfg(windows)]
    {
        match partition_windows(path, ranges) {
            Ok(pieces) => Ok(pieces),
            Err(err) => {
                // Unsupported volume / non-sparse FS → densify (pre-Windows behavior).
                match err.raw_os_error() {
                    Some(1) | Some(50) | Some(87) => Ok(ranges_as_data(ranges)),
                    _ if err.kind() == io::ErrorKind::Unsupported
                        || err.kind() == io::ErrorKind::InvalidInput =>
                    {
                        Ok(ranges_as_data(ranges))
                    }
                    _ => Err(err),
                }
            }
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        Ok(ranges_as_data(ranges))
    }
}

fn ranges_as_data(ranges: &[ByteRange]) -> Vec<Piece> {
    ranges
        .iter()
        .filter(|r| r.end > r.start)
        .map(|r| Piece {
            start: r.start,
            end: r.end,
            hole: false,
        })
        .collect()
}

#[cfg(unix)]
fn partition_unix(path: &Path, ranges: &[ByteRange]) -> io::Result<Vec<Piece>> {
    use std::os::unix::io::AsRawFd;

    let file = File::open(path)?;
    let fd = file.as_raw_fd();
    let mut out = Vec::new();
    for range in ranges {
        if range.end <= range.start {
            continue;
        }
        let mut pos = range.start;
        while pos < range.end {
            match seek_kind(fd, pos, libc::SEEK_DATA) {
                Ok(data_off) => {
                    let data_off = data_off.min(range.end);
                    if data_off > pos {
                        out.push(Piece {
                            start: pos,
                            end: data_off,
                            hole: true,
                        });
                    }
                    if data_off >= range.end {
                        break;
                    }
                    let hole_off = match seek_kind(fd, data_off, libc::SEEK_HOLE) {
                        Ok(h) => h.min(range.end),
                        // ENXIO: no hole before EOF — rest is data.
                        Err(err) if err.raw_os_error() == Some(libc::ENXIO) => range.end,
                        Err(err) => return Err(err),
                    };
                    if hole_off > data_off {
                        out.push(Piece {
                            start: data_off,
                            end: hole_off,
                            hole: false,
                        });
                    }
                    pos = hole_off;
                }
                // ENXIO: no data from pos to EOF — rest of range is a hole.
                Err(err) if err.raw_os_error() == Some(libc::ENXIO) => {
                    out.push(Piece {
                        start: pos,
                        end: range.end,
                        hole: true,
                    });
                    break;
                }
                Err(err) => return Err(err),
            }
        }
    }
    Ok(out)
}

#[cfg(unix)]
fn seek_kind(fd: std::os::unix::io::RawFd, offset: u64, whence: i32) -> io::Result<u64> {
    // Use libc::off_t (i32 on 32-bit Android / armeabi-v7a; i64 elsewhere), not i64.
    let off = libc::off_t::try_from(offset).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "offset too large for lseek")
    })?;
    let ret = unsafe { libc::lseek(fd, off, whence) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as u64)
    }
}

/// Merge allocated `[offset, offset+len)` runs into hole/data pieces covering `range`.
fn pieces_from_allocated(range: ByteRange, allocated: &[(u64, u64)]) -> Vec<Piece> {
    let mut pos = range.start;
    let mut out = Vec::new();
    for &(off, len) in allocated {
        let a0 = off.max(range.start);
        let a1 = off.saturating_add(len).min(range.end);
        if a1 <= a0 {
            continue;
        }
        if a0 > pos {
            out.push(Piece {
                start: pos,
                end: a0,
                hole: true,
            });
        }
        out.push(Piece {
            start: a0,
            end: a1,
            hole: false,
        });
        pos = a1;
    }
    if pos < range.end {
        out.push(Piece {
            start: pos,
            end: range.end,
            hole: true,
        });
    }
    out
}

#[cfg(windows)]
fn partition_windows(path: &Path, ranges: &[ByteRange]) -> io::Result<Vec<Piece>> {
    let file = File::open(path)?;
    let mut out = Vec::new();
    for range in ranges {
        if range.end <= range.start {
            continue;
        }
        let allocated = win::query_allocated_ranges(&file, range.start, range.end)?;
        out.extend(pieces_from_allocated(ByteRange { start: range.start, end: range.end }, &allocated));
    }
    Ok(out)
}

/// Default hole-frame cap for file/tar `send_blob` (u32-safe, cuts sparse RTT).
/// Stream `decoded_chunk` still synthesizes zeros and stays at [`STREAM_MAX_HOLE`].
pub const FILE_MAX_HOLE: u64 = 1 << 30; // 1 GiB

/// Cap for hole frames that stream writers may synthesize into a zero Vec.
pub const STREAM_MAX_HOLE: u64 = 4 * 1024 * 1024;

/// Chunk data pieces to `chunk` bytes; hole pieces split at `max_hole`.
pub fn chunk_pieces(pieces: &[Piece], chunk: usize, max_hole: u64) -> Vec<Piece> {
    let chunk = chunk.max(1) as u64;
    let max_hole = max_hole.max(1);
    let mut out = Vec::new();
    for piece in pieces {
        if piece.len() == 0 {
            continue;
        }
        if piece.hole {
            // File recv uses write_hole (no alloc). Keep frames u32-safe via max_hole.
            let mut off = piece.start;
            while off < piece.end {
                let end = (off + max_hole).min(piece.end);
                out.push(Piece {
                    start: off,
                    end,
                    hole: true,
                });
                off = end;
            }
        } else {
            let mut off = piece.start;
            while off < piece.end {
                let end = (off + chunk).min(piece.end);
                out.push(Piece {
                    start: off,
                    end,
                    hole: false,
                });
                off = end;
            }
        }
    }
    out
}

/// Mark `file` sparse when the OS supports it (NTFS). No-op on Unix — extending
/// with `set_len` already leaves a hole. Best-effort: unsupported volumes Ok(()).
pub fn ensure_sparse(file: &File) -> io::Result<()> {
    #[cfg(windows)]
    {
        win::set_sparse(file)
    }
    #[cfg(not(windows))]
    {
        let _ = file;
        Ok(())
    }
}

/// Ensure `file` is at least `end` bytes, keeping the extension sparse when possible.
pub fn prepare_sparse_len(file: &File, end: u64) -> io::Result<()> {
    ensure_sparse(file)?;
    let cur = file.metadata()?.len();
    if end > cur {
        file.set_len(end)?;
    }
    Ok(())
}

/// Mark `[offset, offset+len)` as a hole without densifying. On Windows this is
/// `FSCTL_SET_SPARSE` + `FSCTL_SET_ZERO_DATA`; on Unix `set_len` for EOF extension
/// (and optional punch when available).
pub fn punch_hole(file: &File, offset: u64, len: u64) -> io::Result<()> {
    if len == 0 {
        return Ok(());
    }
    let end = offset.saturating_add(len);
    prepare_sparse_len(file, end)?;
    #[cfg(windows)]
    {
        win::zero_data(file, offset, end)?;
    }
    #[cfg(all(unix, target_os = "linux"))]
    {
        // Punch mid-file holes so overwriting dense regions goes sparse again.
        // Fails with EOPNOTSUPP on some FS — ignore, set_len already covered EOF.
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        let off = i64::try_from(offset).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "offset too large")
        })?;
        let plen = i64::try_from(len).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "len too large")
        })?;
        // FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE = 0x03
        let rc = unsafe { libc::fallocate(fd, 0x03, off, plen) };
        if rc != 0 {
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EOPNOTSUPP) | Some(libc::ENOSYS) | Some(libc::EINVAL) => {}
                _ => return Err(err),
            }
        }
    }
    let _ = (file, offset, end);
    Ok(())
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::{
        FILE_ALLOCATED_RANGE_BUFFER, FILE_ZERO_DATA_INFORMATION, FSCTL_QUERY_ALLOCATED_RANGES,
        FSCTL_SET_SPARSE, FSCTL_SET_ZERO_DATA,
    };

    fn best_effort(err: io::Error) -> io::Result<()> {
        // FAT/exFAT/SMB often refuse sparse; densify rather than fail the transfer.
        match err.raw_os_error() {
            Some(1) | Some(50) | Some(87) | Some(1_241) => Ok(()), // INVALID_FUNCTION, NOT_SUPPORTED, INVALID_PARAMETER, NOT_A_REPARSE?
            _ => {
                // Also ignore access/volume errors that mean "no sparse here".
                let kind = err.kind();
                if kind == io::ErrorKind::Unsupported
                    || kind == io::ErrorKind::InvalidInput
                {
                    Ok(())
                } else {
                    Err(err)
                }
            }
        }
    }

    pub fn set_sparse(file: &File) -> io::Result<()> {
        let handle = file.as_raw_handle() as HANDLE;
        let mut returned = 0u32;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                FSCTL_SET_SPARSE,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            best_effort(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub fn zero_data(file: &File, offset: u64, end: u64) -> io::Result<()> {
        let handle = file.as_raw_handle() as HANDLE;
        let info = FILE_ZERO_DATA_INFORMATION {
            FileOffset: offset as i64,
            BeyondFinalZero: end as i64,
        };
        let mut returned = 0u32;
        let ok = unsafe {
            DeviceIoControl(
                handle,
                FSCTL_SET_ZERO_DATA,
                &info as *const _ as *const _,
                std::mem::size_of::<FILE_ZERO_DATA_INFORMATION>() as u32,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            best_effort(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    /// Returns allocated `(offset, length)` runs intersecting `[start, end)`.
    pub fn query_allocated_ranges(
        file: &File,
        start: u64,
        end: u64,
    ) -> io::Result<Vec<(u64, u64)>> {
        if end <= start {
            return Ok(Vec::new());
        }
        let handle = file.as_raw_handle() as HANDLE;
        let input = FILE_ALLOCATED_RANGE_BUFFER {
            FileOffset: start as i64,
            Length: (end - start) as i64,
        };
        let mut buf_size = 4096usize;
        loop {
            let mut out = vec![0u8; buf_size];
            let mut returned = 0u32;
            let ok = unsafe {
                DeviceIoControl(
                    handle,
                    FSCTL_QUERY_ALLOCATED_RANGES,
                    &input as *const _ as *const _,
                    std::mem::size_of::<FILE_ALLOCATED_RANGE_BUFFER>() as u32,
                    out.as_mut_ptr() as *mut _,
                    buf_size as u32,
                    &mut returned,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                let err = io::Error::last_os_error();
                // ERROR_MORE_DATA = 234
                if err.raw_os_error() == Some(234) {
                    buf_size = buf_size.saturating_mul(2).max(buf_size + 4096);
                    if buf_size > 16 * 1024 * 1024 {
                        return Err(err);
                    }
                    continue;
                }
                return Err(err);
            }
            let sz = std::mem::size_of::<FILE_ALLOCATED_RANGE_BUFFER>();
            let n = (returned as usize) / sz;
            let mut ranges = Vec::with_capacity(n);
            for i in 0..n {
                let off = i * sz;
                let slice = &out[off..off + sz];
                let mut tmp = FILE_ALLOCATED_RANGE_BUFFER {
                    FileOffset: 0,
                    Length: 0,
                };
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        slice.as_ptr(),
                        &mut tmp as *mut _ as *mut u8,
                        sz,
                    );
                }
                if tmp.Length > 0 {
                    ranges.push((tmp.FileOffset as u64, tmp.Length as u64));
                }
            }
            return Ok(ranges);
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom, Write};

    #[test]
    fn dense_file_is_all_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dense.bin");
        std::fs::write(&path, vec![b'x'; 64 * 1024]).unwrap();
        let pieces = partition(
            &path,
            &[ByteRange {
                start: 0,
                end: 64 * 1024,
            }],
        )
        .unwrap();
        assert_eq!(pieces.len(), 1);
        assert!(!pieces[0].hole);
        assert_eq!(pieces[0].start, 0);
        assert_eq!(pieces[0].end, 64 * 1024);
    }

    #[cfg(unix)]
    #[test]
    fn sparse_file_reports_holes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sparse.bin");
        let mut f = File::create(&path).unwrap();
        f.seek(SeekFrom::Start(2 * 1024 * 1024)).unwrap();
        f.write_all(&[1, 2, 3, 4]).unwrap();
        f.seek(SeekFrom::Start(4 * 1024 * 1024)).unwrap();
        f.write_all(&[0]).unwrap(); // force EOF at 4MiB+1 via set_len below
        drop(f);
        // 4 MiB logical, 4 bytes of data near 2 MiB.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap();
        f.set_len(4 * 1024 * 1024).unwrap();
        // Rewrite the data after truncate.
        f.seek(SeekFrom::Start(2 * 1024 * 1024)).unwrap();
        f.write_all(&[1, 2, 3, 4]).unwrap();
        drop(f);

        let pieces = partition(
            &path,
            &[ByteRange {
                start: 0,
                end: 4 * 1024 * 1024,
            }],
        )
        .unwrap();
        let holes: u64 = pieces.iter().filter(|p| p.hole).map(|p| p.len()).sum();
        let data: u64 = pieces.iter().filter(|p| !p.hole).map(|p| p.len()).sum();
        assert!(holes > 3 * 1024 * 1024, "holes={holes} pieces={pieces:?}");
        assert!(data >= 4 && data < 1024 * 1024, "data={data} pieces={pieces:?}");
        assert_eq!(holes + data, 4 * 1024 * 1024);
    }

    #[test]
    fn chunk_pieces_splits_large_holes() {
        let pieces = vec![
            Piece {
                start: 0,
                end: 8 * 1024 * 1024,
                hole: true,
            },
            Piece {
                start: 8 * 1024 * 1024,
                end: 8 * 1024 * 1024 + 3000,
                hole: false,
            },
        ];
        let chunked = chunk_pieces(&pieces, 1024, 4 * 1024 * 1024);
        assert!(chunked[0].hole);
        assert_eq!(chunked[0].len(), 4 * 1024 * 1024);
        assert!(chunked[1].hole);
        assert_eq!(chunked[1].len(), 4 * 1024 * 1024);
        assert!(!chunked[2].hole);
        assert_eq!(chunked[2].len(), 1024);
    }


    #[test]
    fn pieces_from_allocated_inserts_holes_around_data() {
        let range = ByteRange {
            start: 0,
            end: 100,
        };
        let pieces = pieces_from_allocated(range, &[(40, 10)]);
        assert_eq!(
            pieces,
            vec![
                Piece {
                    start: 0,
                    end: 40,
                    hole: true
                },
                Piece {
                    start: 40,
                    end: 50,
                    hole: false
                },
                Piece {
                    start: 50,
                    end: 100,
                    hole: true
                },
            ]
        );
        // No allocated → whole range is a hole.
        assert_eq!(
            pieces_from_allocated(range, &[]),
            vec![Piece {
                start: 0,
                end: 100,
                hole: true
            }]
        );
        // Fully allocated.
        assert_eq!(
            pieces_from_allocated(range, &[(0, 100)]),
            vec![Piece {
                start: 0,
                end: 100,
                hole: false
            }]
        );
    }

    #[cfg(unix)]
    #[test]
    fn seek_kind_offset_converts_via_off_t() {
        // Pins the Android armeabi-v7a-safe conversion: lseek takes off_t, which
        // is i32 on 32-bit targets. Building with i64::try_from alone fails typeck.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seek.bin");
        std::fs::write(&path, b"abcdefgh").unwrap();
        let file = File::open(&path).unwrap();
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        let pos = seek_kind(fd, 3, libc::SEEK_SET).unwrap();
        assert_eq!(pos, 3);
        // Values that cannot fit off_t must error (only observable when off_t is
        // narrower than u64; on 64-bit hosts off_t is typically i64 so this is a
        // no-op bound check for near-max u64).
        let too_big = u64::MAX;
        if libc::off_t::try_from(too_big).is_err() {
            let err = seek_kind(fd, too_big, libc::SEEK_SET).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn chunk_pieces_file_max_hole_keeps_one_gib_frame() {
        let pieces = vec![Piece {
            start: 0,
            end: 128 * 1024 * 1024,
            hole: true,
        }];
        let chunked = chunk_pieces(&pieces, 1024, FILE_MAX_HOLE);
        assert_eq!(chunked.len(), 1);
        assert!(chunked[0].hole);
        assert_eq!(chunked[0].len(), 128 * 1024 * 1024);
    }
}
