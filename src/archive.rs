//! Bounded, in-memory archive scanning. Members are never extracted to disk.
use std::io::{Cursor, Read};

use anyhow::{Result, bail};
use flate2::read::MultiGzDecoder;

use crate::{Engine, ScanReport, scan::ScanControl};

const MAX_DEPTH: usize = 4;

#[derive(Clone, Copy)]
enum Format {
    Zip,
    Tar,
    Gzip,
}

fn format(name: &str, bytes: &[u8]) -> Option<Format> {
    let name = name.to_ascii_lowercase();
    if bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || name.ends_with(".zip")
    {
        Some(Format::Zip)
    } else if bytes.starts_with(b"\x1f\x8b") || name.ends_with(".gz") || name.ends_with(".tgz") {
        Some(Format::Gzip)
    } else if bytes.get(257..262) == Some(b"ustar") || name.ends_with(".tar") {
        Some(Format::Tar)
    } else {
        None
    }
}

/// Scan ZIP, tar, or gzip, including at most four nested archive layers.
///
/// `max_bytes` bounds cumulative decompressed bytes, including nested container
/// bytes. Members share the budget. Unsupported formats return `None`; malformed
/// top-level containers return an error. Bad nested members and resource limits
/// make the report incomplete while preserving findings in other members.
/// `stats.files` and `stats.bytes` count scanned leaf members only.
pub fn scan_archive(
    engine: &Engine,
    name: &str,
    bytes: &[u8],
    max_bytes: u64,
) -> Result<Option<ScanReport>> {
    scan_archive_with_identity(
        engine,
        name,
        name,
        bytes,
        max_bytes,
        &ScanControl::default(),
    )
}

/// Scan an archive with a stable logical identity and cooperative cancellation.
/// Display paths continue to select rules; member identities determine fingerprints.
pub fn scan_archive_with_identity(
    engine: &Engine,
    name: &str,
    identity: &str,
    bytes: &[u8],
    max_bytes: u64,
    control: &ScanControl,
) -> Result<Option<ScanReport>> {
    let Some(kind) = format(name, bytes) else {
        return Ok(None);
    };
    let mut state = State {
        engine,
        remaining: max_bytes,
        report: ScanReport::default(),
        control,
        cancelled: false,
    };
    state.archive(name, identity, bytes, kind, 0)?;
    Ok(Some(state.report))
}

struct State<'a> {
    engine: &'a Engine,
    remaining: u64,
    report: ScanReport,
    control: &'a ScanControl,
    cancelled: bool,
}

impl State<'_> {
    fn skip(&mut self, name: &str, message: &str) {
        self.report.stats.skipped += 1;
        self.report.fail(name, message);
    }

    fn cancelled(&mut self, name: &str) -> bool {
        if self.control.is_cancelled() {
            if !self.cancelled {
                self.cancelled = true;
                self.skip(name, "scan cancelled");
            }
            true
        } else {
            false
        }
    }

    fn read(&mut self, name: &str, reader: impl Read) -> Result<Option<Vec<u8>>> {
        let mut bytes = Vec::new();
        // Bound each decompressor read so cancellation does not wait for a
        // complete member. Never reserve an untrusted advertised member size.
        let mut reader = reader.take(self.remaining.saturating_add(1));
        let mut buffer = [0; 16 * 1024];
        loop {
            if self.cancelled(name) {
                return Ok(None);
            }
            let count = match reader.read(&mut buffer) {
                Ok(count) => count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => bail!("archive member decompression or integrity check failed"),
            };
            if count == 0 {
                return Ok(Some(bytes));
            }
            if count as u64 > self.remaining {
                self.remaining = 0;
                self.skip(name, "archive cumulative decompressed byte limit exceeded");
                return Ok(None);
            }
            self.remaining -= count as u64;
            bytes.extend_from_slice(&buffer[..count]);
        }
    }

    fn member(&mut self, name: &str, identity: &str, bytes: &[u8], depth: usize) {
        if self.cancelled(name) {
            return;
        }
        if let Some(kind) = format(name, bytes) {
            if depth >= MAX_DEPTH {
                self.skip(name, "archive nesting depth limit exceeded");
            } else if self.archive(name, identity, bytes, kind, depth).is_err() {
                self.skip(name, "nested archive is corrupt or unsupported");
            }
            return;
        }
        self.report.stats.files += 1;
        self.report.stats.bytes += bytes.len() as u64;
        self.report.stats.detection_passes += 1;
        match self.engine.scan_bytes_with_identity(name, identity, bytes) {
            Ok(mut findings) => {
                for finding in &mut findings {
                    finding.coordinate_space = if finding.coordinate_space == "source_bytes" {
                        "archive_member_bytes".into()
                    } else {
                        format!("archive_member_{}", finding.coordinate_space)
                    };
                }
                self.report.findings.extend(findings);
            }
            Err(_) => self.report.fail(name, "archive member detection failed"),
        }
    }

    fn archive(
        &mut self,
        name: &str,
        identity: &str,
        bytes: &[u8],
        kind: Format,
        depth: usize,
    ) -> Result<()> {
        if self.cancelled(name) {
            return Ok(());
        }
        match kind {
            Format::Zip => {
                let Ok(mut archive) = zip::ZipArchive::new(Cursor::new(bytes)) else {
                    bail!("invalid ZIP archive");
                };
                for index in 0..archive.len() {
                    if self.cancelled(name) {
                        break;
                    }
                    let Ok(mut entry) = archive.by_index(index) else {
                        self.skip(name, "cannot decode ZIP member");
                        continue;
                    };
                    if entry.is_dir() {
                        continue;
                    }
                    // A name zip cannot decode still gets scanned, under its raw bytes.
                    let member = entry.name().map_or_else(
                        |_| String::from_utf8_lossy(entry.name_raw()).into_owned(),
                        |decoded| decoded.into_owned(),
                    );
                    let path = format!("{name}!{member}");
                    let member_identity = format!("{identity}!{member}");
                    match self.read(&path, &mut entry) {
                        Ok(Some(data)) => self.member(&path, &member_identity, &data, depth + 1),
                        Ok(None) => break,
                        Err(_) => {
                            self.skip(&path, "ZIP member decompression or integrity check failed")
                        }
                    }
                }
            }
            Format::Tar => {
                // A tar container must contain at least one complete header block.
                if bytes.len() < 512 {
                    bail!("truncated tar archive");
                }
                let mut archive = tar::Archive::new(Cursor::new(bytes));
                let Ok(entries) = archive.entries() else {
                    bail!("invalid tar archive");
                };
                for (index, entry) in entries.enumerate() {
                    if self.cancelled(name) {
                        break;
                    }
                    let mut entry = match entry {
                        Ok(entry) => entry,
                        Err(_) if index == 0 => bail!("invalid tar archive header"),
                        Err(_) => {
                            self.skip(name, "invalid tar member header");
                            break;
                        }
                    };
                    if entry.header().entry_type().is_dir() {
                        continue;
                    }
                    let path_bytes = entry.path_bytes();
                    let Ok(member_name) = std::str::from_utf8(&path_bytes) else {
                        self.skip(name, "tar member path is not UTF-8");
                        continue;
                    };
                    let path = format!("{name}!{member_name}");
                    let member_identity = format!("{identity}!{member_name}");
                    if !entry.header().entry_type().is_file() {
                        self.skip(&path, "unsupported tar member type; links are not followed");
                        continue;
                    }
                    match self.read(&path, &mut entry) {
                        Ok(Some(data)) => self.member(&path, &member_identity, &data, depth + 1),
                        Ok(None) => break,
                        Err(_) => self.skip(&path, "tar member is truncated or unreadable"),
                    }
                }
            }
            Format::Gzip => {
                let basename = name.rsplit(['!', '/', '\\']).next().unwrap_or(name);
                let lower = basename.to_ascii_lowercase();
                let inner = if lower.ends_with(".tgz") {
                    format!("{}.tar", &basename[..basename.len() - 4])
                } else if lower.ends_with(".gz") {
                    basename[..basename.len() - 3].to_owned()
                } else {
                    "content".to_owned()
                };
                let path = format!("{name}!{inner}");
                let member_identity = format!("{identity}!{inner}");
                if let Some(data) = self.read(&path, MultiGzDecoder::new(bytes))? {
                    self.member(&path, &member_identity, &data, depth + 1);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EngineConfig;

    #[test]
    fn cancellation_stops_between_read_chunks_and_preserves_prior_findings() {
        struct CancelAfterRead<'a> {
            control: &'a ScanControl,
            reads: usize,
        }
        impl Read for CancelAfterRead<'_> {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                self.reads += 1;
                buffer.fill(b'x');
                self.control.cancel();
                Ok(buffer.len())
            }
        }
        let engine = Engine::new(EngineConfig::default()).unwrap();
        let control = ScanControl::default();
        let mut state = State {
            engine: &engine,
            remaining: 1_000_000,
            report: ScanReport::default(),
            control: &control,
            cancelled: false,
        };
        // Synthetic provider-shaped fixture; never issued by a provider.
        let fixture = format!("ghp_{}", "aZ7kP2mQ9xT4vR6n".repeat(3));
        state.member(
            "bundle.zip!first.txt",
            "stable!first.txt",
            fixture.as_bytes(),
            1,
        );
        assert!(!state.report.findings.is_empty());
        let prior_findings = state.report.findings.clone();
        let mut reader = CancelAfterRead {
            control: &control,
            reads: 0,
        };
        assert!(
            state
                .read("bundle.zip!large.txt", &mut reader)
                .unwrap()
                .is_none()
        );
        assert_eq!(reader.reads, 1);
        assert_eq!(state.remaining, 1_000_000 - 16 * 1024);
        assert_eq!(state.report.findings, prior_findings);
        assert_eq!(state.report.exit_code(), 2);
        assert_eq!(state.report.errors.len(), 1);
    }
}
