//! Shipped-payload classification and inventory types.
//!
//! Every relevant file under an analysis target receives exactly one
//! [`PayloadEntry`] with a deterministic [`CoverageState`]. "No analyzer for
//! this language" is visible (`Unsupported`), never silently clean. In S1 no
//! language analyzers are wired yet, so fully inventoried files report
//! `Unsupported`; later slices move files to `Analyzed`/`Partial` as policy
//! identity changes, never as plugin drift.

use serde::Serialize;
use sha2::{Digest, Sha256};

/// What a file is, decided from its path, mode, and content prefix.
/// Serialized names must stay identical to [`PayloadKind::as_str`]; the two
/// acronyms kebab-case would split are overridden explicitly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PayloadKind {
    Qml,
    #[serde(rename = "javascript")]
    JavaScript,
    Shell,
    Python,
    ExtensionlessExecutable,
    ElfBinary,
    #[serde(rename = "macho-binary")]
    MachOBinary,
    PeBinary,
    DataBinary,
    TextFile,
    Symlink,
    Directory,
    Special,
}

impl PayloadKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            PayloadKind::Qml => "qml",
            PayloadKind::JavaScript => "javascript",
            PayloadKind::Shell => "shell",
            PayloadKind::Python => "python",
            PayloadKind::ExtensionlessExecutable => "extensionless-executable",
            PayloadKind::ElfBinary => "elf-binary",
            PayloadKind::MachOBinary => "macho-binary",
            PayloadKind::PeBinary => "pe-binary",
            PayloadKind::DataBinary => "data-binary",
            PayloadKind::TextFile => "text-file",
            PayloadKind::Symlink => "symlink",
            PayloadKind::Directory => "directory",
            PayloadKind::Special => "special",
        }
    }
}

/// Analysis coverage of one inventoried entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CoverageState {
    /// A language analyzer in the current policy processed the content.
    Analyzed,
    /// Some analysis applied; conclusions are explicitly incomplete.
    Partial,
    /// Content was not ingested (oversize or budget exhausted before read).
    Skipped,
    /// Ingestion was cut short mid-file by an error.
    Truncated,
    /// Fully inventoried, but no analyzer covers this language in the
    /// current policy. Never interpreted as clean behavior.
    Unsupported,
    /// Analyzers ran and produced neither findings nor capability
    /// observations for this entry (S3 onward; never emitted before then).
    /// Says "nothing was observed", not "nothing can be wrong".
    Unreferenced,
}

impl CoverageState {
    pub fn as_str(&self) -> &'static str {
        match self {
            CoverageState::Analyzed => "analyzed",
            CoverageState::Partial => "partial",
            CoverageState::Skipped => "skipped",
            CoverageState::Truncated => "truncated",
            CoverageState::Unsupported => "unsupported",
            CoverageState::Unreferenced => "unreferenced",
        }
    }
}

/// One inventoried payload entry. Field order is the canonical serialization
/// order; do not reorder without bumping the policy identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PayloadEntry {
    pub relative_path: String,
    pub kind: PayloadKind,
    /// Raw Unix mode bits (0 on platforms without them).
    pub mode: u32,
    /// Logical size in bytes; symlink target length for symlinks.
    pub size: u64,
    /// Hex SHA-256 of the content actually hashed: full content, or the
    /// head/tail sample recorded when ingestion skipped the middle.
    pub sha256_sampled: Option<String>,
    /// True when the digest covers only head/tail samples, not the whole file.
    pub sampled_digest: bool,
    pub executable: bool,
    pub coverage_state: CoverageState,
    /// Symlink target as stored, never followed.
    pub link_target: Option<String>,
    /// True once an invocation edge from analyzed QML/JS points at this entry
    /// (S3). Purely additive context; the coverage state still governs the
    /// analysis meaning.
    pub invocation_target: bool,
    /// Git object id for pinned-revision ingestion, enabling bounded raw-blob
    /// re-reads without a worktree. `None` for filesystem frontends.
    pub object_id: Option<String>,
}

/// Aggregate view over one completed inventory pass.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PayloadInventory {
    pub entries: Vec<PayloadEntry>,
    pub total_files_seen: usize,
    pub total_bytes_ingested: u64,
    pub limitations: Vec<String>,
}

impl PayloadInventory {
    pub fn state_count(&self, state: CoverageState) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.coverage_state == state)
            .count()
    }

    pub fn sort_entries(&mut self) {
        self.entries.sort_by(|a, b| {
            a.relative_path
                .cmp(&b.relative_path)
                .then_with(|| format!("{:?}", a.kind).cmp(&format!("{:?}", b.kind)))
        });
    }
}

/// Decides [`PayloadKind`] for a regular file from its name, mode, and the
/// first up-to-64KiB of content (the same sniff window philosophy as Git).
///
/// Precedence: native magic first (an ELF named `payload.js` is a binary, not
/// a script), then filename extension, then shebang, then executable/extension
/// and NUL-sniffing fallthroughs. Binary detection is NUL-byte presence inside
/// the sniff window.
pub fn classify_regular_file(path: &str, mode: u32, content_prefix: &[u8]) -> PayloadKind {
    let executable = is_executable(mode);
    let name = path.rsplit('/').next().unwrap_or(path);

    if let Some(kind) = native_magic(content_prefix) {
        return kind;
    }

    if let Some(kind) = kind_by_extension(name) {
        return kind;
    }

    if let Some(interpreter) = shebang_interpreter(content_prefix) {
        let basename = interpreter.rsplit('/').next().unwrap_or(&interpreter);
        match basename {
            "sh" | "bash" | "zsh" | "dash" | "ksh" | "ash" => return PayloadKind::Shell,
            "python" | "python2" | "python3" => return PayloadKind::Python,
            _ => {}
        }
        // A shebang names some other interpreter: it is still a script meant
        // to be executed directly.
        if executable {
            return PayloadKind::ExtensionlessExecutable;
        }
        return PayloadKind::TextFile;
    }

    if executable && !name.contains('.') {
        return PayloadKind::ExtensionlessExecutable;
    }

    if content_prefix.contains(&0u8) {
        return PayloadKind::DataBinary;
    }

    if executable {
        return PayloadKind::ExtensionlessExecutable;
    }

    PayloadKind::TextFile
}

fn kind_by_extension(name: &str) -> Option<PayloadKind> {
    let lower = name.to_ascii_lowercase();
    let extension = lower.rsplit_once('.').map(|(_, ext)| ext)?;
    match extension {
        "qml" => Some(PayloadKind::Qml),
        "js" | "mjs" | "cjs" => Some(PayloadKind::JavaScript),
        "sh" | "bash" | "zsh" => Some(PayloadKind::Shell),
        "py" => Some(PayloadKind::Python),
        _ => None,
    }
}

fn is_executable(mode: u32) -> bool {
    mode & 0o111 != 0
}

/// Returns the interpreter path from a `#!` first line, if present.
fn shebang_interpreter(prefix: &[u8]) -> Option<String> {
    let rest = prefix.strip_prefix(b"#!")?;
    let line_end = rest
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(rest.len());
    let line = std::str::from_utf8(&rest[..line_end]).ok()?;
    // `env(1)` indirection resolves to its argument; anything else is used as-is.
    let line = line.trim_start_matches("/usr/bin/env ");
    let interpreter = line.split_whitespace().next()?;
    Some(interpreter.to_owned())
}

/// Native executable-format magics. The Mach-O fat magic `0xcafebabe` is
/// deliberately not detected because it collides with Java class files, and
/// PE detection requires the `PE\0\0` signature at the `e_lfanew` offset —
/// two leading `MZ` bytes alone would misclassify scripts like `MZ=1`.
fn native_magic(prefix: &[u8]) -> Option<PayloadKind> {
    if prefix.starts_with(b"\x7fELF") {
        return Some(PayloadKind::ElfBinary);
    }
    if prefix.starts_with(b"MZ") && has_pe_signature(prefix) {
        return Some(PayloadKind::PeBinary);
    }
    const MACH_O_MAGICS: [&[u8]; 4] = [
        &[0xfe, 0xed, 0xfa, 0xce], // 32-bit big-endian
        &[0xce, 0xfa, 0xed, 0xfe], // 32-bit little-endian
        &[0xfe, 0xed, 0xfa, 0xcf], // 64-bit big-endian
        &[0xcf, 0xfa, 0xed, 0xfe], // 64-bit little-endian
    ];
    if MACH_O_MAGICS.iter().any(|magic| prefix.starts_with(magic)) {
        return Some(PayloadKind::MachOBinary);
    }
    None
}

fn has_pe_signature(prefix: &[u8]) -> bool {
    let Some(offset_bytes) = prefix.get(0x3c..0x40) else {
        return false;
    };
    let lfanew = u32::from_le_bytes([
        offset_bytes[0],
        offset_bytes[1],
        offset_bytes[2],
        offset_bytes[3],
    ]) as usize;
    prefix.get(lfanew..lfanew + 4) == Some(b"PE\0\0")
}

/// Streaming SHA-256 over exactly the bytes fed in.
#[derive(Default)]
pub struct ContentDigester {
    hasher: Sha256,
    bytes_hashed: u64,
}

impl ContentDigester {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, chunk: &[u8]) {
        self.hasher.update(chunk);
        self.bytes_hashed += chunk.len() as u64;
    }

    pub fn finish_hex(self) -> (String, u64) {
        (
            self.hasher
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            self.bytes_hashed,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NON_EXEC: u32 = 0o644;
    const EXEC: u32 = 0o755;

    #[test]
    fn native_magic_outranks_lying_extensions() {
        assert_eq!(
            classify_regular_file("payload.js", EXEC, b"\x7fELF\x02\x01\x01"),
            PayloadKind::ElfBinary,
            "an ELF named .js must stay visible as a binary"
        );
        assert_eq!(
            classify_regular_file("tool.sh", EXEC, b""),
            PayloadKind::Shell
        );
        assert_eq!(
            classify_regular_file("app.py", NON_EXEC, b""),
            PayloadKind::Python
        );
    }

    #[test]
    fn shebang_interpreters_match_exact_basenames() {
        assert_eq!(
            classify_regular_file("run", EXEC, b"#!/bin/sh\nset -e\n"),
            PayloadKind::Shell
        );
        assert_eq!(
            classify_regular_file("run", EXEC, b"#!/usr/bin/env python3\ncode\n"),
            PayloadKind::Python
        );
        // `wish` contains "sh" as a substring but is not a shell.
        assert_eq!(
            classify_regular_file("gui", EXEC, b"#!/usr/bin/wish\npack .\n"),
            PayloadKind::ExtensionlessExecutable
        );
        assert_eq!(
            classify_regular_file("weird", EXEC, b"#!/opt/tool/engine\nx"),
            PayloadKind::ExtensionlessExecutable
        );
        assert_eq!(
            classify_regular_file("notes", NON_EXEC, b"#!not-a-script-start"),
            PayloadKind::TextFile,
            "shebang must be at offset zero"
        );
    }

    #[test]
    fn native_magics_and_nul_sniffing() {
        assert_eq!(
            classify_regular_file("bin/proc", EXEC, b"\x7fELF\x02\x01\x01"),
            PayloadKind::ElfBinary
        );
        // A realistic PE header: MZ + e_lfanew pointing at PE\0\0.
        let mut pe = vec![0u8; 0x40];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        pe.extend_from_slice(b"PE\0\0");
        assert_eq!(
            classify_regular_file("bin/proc", EXEC, &pe),
            PayloadKind::PeBinary
        );
        // `MZ=1` is a valid shell script line, not a PE binary.
        assert_eq!(
            classify_regular_file("env.sh", EXEC, b"MZ=1\nexport X\n"),
            PayloadKind::Shell,
            "bare MZ must not win over the extension"
        );
        assert_eq!(
            classify_regular_file("bin/proc", EXEC, &[0xcf, 0xfa, 0xed, 0xfe, 0x00]),
            PayloadKind::MachOBinary
        );
        assert_eq!(
            classify_regular_file("blob.dat", NON_EXEC, b"abc\x00def"),
            PayloadKind::DataBinary
        );
        assert_eq!(
            classify_regular_file("java.class", NON_EXEC, &[0xca, 0xfe, 0xba, 0xbe, 0x00]),
            PayloadKind::DataBinary,
            "cafebabe stays ambiguous, not Mach-O"
        );
    }

    #[test]
    fn extensionless_executables_are_visible() {
        assert_eq!(
            classify_regular_file("payload", EXEC, b"\xff\xfe\x00garbage"),
            PayloadKind::ExtensionlessExecutable
        );
        assert_eq!(
            classify_regular_file("payload.bin", EXEC, b"\xff\xfe\x00garbage"),
            PayloadKind::DataBinary,
            "extension suppresses the extensionless rule"
        );
    }

    #[test]
    fn plain_text_falls_through() {
        assert_eq!(
            classify_regular_file("README.md", NON_EXEC, b"# hello\nworld\n"),
            PayloadKind::TextFile
        );
    }

    #[test]
    fn digester_hashes_incrementally() {
        let mut digester = ContentDigester::new();
        digester.update(b"hello ");
        digester.update(b"world");
        let (hex, len) = digester.finish_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(len, 11);
    }

    #[test]
    fn coverage_states_render_documented_names() {
        assert_eq!(CoverageState::Unsupported.as_str(), "unsupported");
        assert_eq!(CoverageState::Skipped.as_str(), "skipped");
        assert_eq!(
            PayloadKind::ExtensionlessExecutable.as_str(),
            "extensionless-executable"
        );
    }
}
