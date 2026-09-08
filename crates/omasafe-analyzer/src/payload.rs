//! Shipped-payload classification and inventory types.
//!
//! Every relevant file under an analysis target receives exactly one
//! [`PayloadEntry`] with a deterministic [`CoverageState`]. "No analyzer for
//! this language" is visible (`Unsupported`), never silently clean. In S1 no
//! language analyzers are wired yet, so fully inventoried files report
//! `Unsupported`; later slices move files to `Analyzed`/`Partial` as policy
//! identity changes, never as plugin drift.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
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

/// Whether the bytes and metadata needed for classification were collected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InventoryState {
    Complete,
    Incomplete,
}

/// Confidence and source for an open language hint. The language string is
/// intentionally open: recognizing a language does not add an analyzer or a
/// serialized enum variant that strict consumers must understand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LanguageHint {
    pub language: String,
    pub confidence: String,
    pub source: String,
}

/// Syntax coverage is separate from language recognition and behavior
/// coverage. In particular, a recognized Node or Ruby script remains
/// unsupported behavior in this release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SyntaxCoverage {
    Parser,
    LexicalFallback,
    Unsupported,
    Unavailable,
    Bounded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BehaviorCoverage {
    Modeled,
    Partial,
    Unsupported,
    Unavailable,
    Bounded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CodeExposure {
    EntryPoint,
    KnownExecuteOrLoad,
    PossibleOrDynamic,
    ExplicitlyUnreferenced,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContentClass {
    NativeCode,
    InterpretedCode,
    ArchiveOrContainer,
    BytecodeOrWasm,
    OrdinaryData,
    Unknown,
}

/// Additive per-entry v0.2.5 coverage model. It lives beside the legacy
/// `PayloadEntry` so Rust callers that construct the v0.2 inventory remain
/// source-compatible while report consumers gain orthogonal state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadCoverage {
    pub relative_path: String,
    pub inventory_state: InventoryState,
    pub language_hint: Option<LanguageHint>,
    pub syntax_coverage: SyntaxCoverage,
    pub behavior_coverage: BehaviorCoverage,
    pub code_exposure: CodeExposure,
    pub content_class: ContentClass,
    pub exact_sha256: Option<String>,
    pub digest_state: String,
    pub native_format: Option<String>,
    pub architecture: Option<String>,
    pub classification_evidence: Vec<String>,
    pub opaque_review_required: bool,
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
    /// Orthogonal v0.2.5 coverage records, keyed by `relative_path` in
    /// deterministic order. Empty means a legacy producer supplied only the
    /// v0.2 inventory; callers can materialize it with `refresh_coverage`.
    #[serde(default)]
    pub coverage: Vec<PayloadCoverage>,
    /// Native architecture facts are retained separately from the legacy
    /// entry shape so older Rust producers can still construct entries.
    #[serde(default)]
    pub native_architectures: BTreeMap<String, String>,
    /// Bounded content-class facts derived from the classification prefix.
    /// This keeps archives/WASM/bytecode typed even when their legacy
    /// `PayloadKind` remains `DataBinary` for consumer compatibility.
    #[serde(default)]
    pub content_classes: BTreeMap<String, ContentClass>,
    /// Open language hints retained from the bounded classification prefix.
    /// These preserve Node/Ruby/etc. recognition without adding closed
    /// `PayloadKind` variants or claiming behavior support.
    #[serde(default)]
    pub language_hints: BTreeMap<String, LanguageHint>,
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

    /// Materialize additive coverage records from the legacy inventory fields.
    /// Reference state is read after analysis so known execute/load edges are
    /// represented without changing the old enum values.
    pub fn refresh_coverage(&mut self) {
        self.coverage = self
            .entries
            .iter()
            .map(|entry| {
                payload_coverage_with_metadata(
                    entry,
                    self.native_architectures
                        .get(&entry.relative_path)
                        .map(String::as_str),
                    self.language_hints.get(&entry.relative_path),
                    self.content_classes.get(&entry.relative_path),
                )
            })
            .collect();
        self.coverage
            .sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
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

/// Return the direct interpreter basename from a shebang without executing
/// `env`. Supports direct paths, `/usr/bin/env`, `/bin/env`, `env -S`, and the
/// conventional `--` separator. Options before the interpreter are skipped.
pub fn shebang_interpreter(content_prefix: &[u8]) -> Option<String> {
    let rest = content_prefix.strip_prefix(b"#!")?;
    let line_end = rest
        .iter()
        .position(|byte| *byte == b'\n' || *byte == b'\r')
        .unwrap_or(rest.len());
    let line = std::str::from_utf8(&rest[..line_end]).ok()?;
    let mut words = line.split_whitespace();
    let first = words.next()?;
    let first_basename = first.rsplit('/').next().unwrap_or(first);
    if first_basename != "env" {
        return Some(first.to_owned());
    }
    let mut word = words.next()?;
    if word == "-S" || word == "--split-string" {
        word = words.next()?;
    }
    while word.starts_with('-') && word != "--" {
        word = words.next()?;
    }
    if word == "--" {
        word = words.next()?;
    }
    Some(word.to_owned())
}

/// Open language recognition is deliberately independent from the closed
/// `PayloadKind` enum. `source` is the evidence used to make the hint.
pub fn language_hint(path: &str, content_prefix: &[u8]) -> Option<LanguageHint> {
    let name = path.rsplit('/').next().unwrap_or(path);
    let lower = name.to_ascii_lowercase();
    let extension_hint = lower.rsplit_once('.').and_then(|(_, extension)| {
        let language = match extension {
            "qml" => "qml",
            "js" | "mjs" | "cjs" => "javascript",
            "ts" | "mts" | "cts" => "typescript",
            "py" | "pyw" => "python",
            "sh" | "bash" | "zsh" | "dash" | "ksh" | "ash" => "shell",
            "fish" => "fish",
            "rb" => "ruby",
            "pl" | "pm" => "perl",
            "lua" => "lua",
            "php" => "php",
            "ps1" => "powershell",
            _ => return None,
        };
        Some(LanguageHint {
            language: language.to_owned(),
            confidence: "exact".to_owned(),
            source: "extension".to_owned(),
        })
    });
    let shebang_hint = shebang_interpreter(content_prefix).and_then(|interpreter| {
        let basename = interpreter.rsplit('/').next().unwrap_or(&interpreter);
        let language = match basename {
            "sh" | "bash" | "zsh" | "dash" | "ksh" | "ash" => "shell",
            "fish" => "fish",
            "python" | "python2" | "python3" => "python",
            "node" | "nodejs" | "deno" | "bun" => "javascript",
            "ruby" => "ruby",
            "perl" => "perl",
            "lua" => "lua",
            "php" => "php",
            "pwsh" | "powershell" => "powershell",
            _ => return None,
        };
        Some(LanguageHint {
            language: language.to_owned(),
            confidence: "exact".to_owned(),
            source: "shebang".to_owned(),
        })
    });
    match (extension_hint, shebang_hint) {
        (Some(extension), Some(shebang)) if extension.language != shebang.language => {
            Some(LanguageHint {
                language: format!("{}|{}", extension.language, shebang.language),
                confidence: "conflict".to_owned(),
                source: "extension-and-shebang".to_owned(),
            })
        }
        (Some(extension), _) => Some(extension),
        (_, Some(shebang)) => Some(shebang),
        _ => None,
    }
}

/// Derive the additive v0.2.5 coverage row for one legacy inventory entry.
pub fn payload_coverage(entry: &PayloadEntry) -> PayloadCoverage {
    payload_coverage_with_metadata(entry, None, None, None)
}

fn payload_coverage_with_metadata(
    entry: &PayloadEntry,
    architecture: Option<&str>,
    language_hint_override: Option<&LanguageHint>,
    content_class_override: Option<&ContentClass>,
) -> PayloadCoverage {
    let native = native_format_for_kind(&entry.kind);
    let interpreted = matches!(
        entry.kind,
        PayloadKind::Qml | PayloadKind::JavaScript | PayloadKind::Shell | PayloadKind::Python
    );
    let hint = if native.is_some() {
        None
    } else if let Some(hint) = language_hint_override {
        Some(hint.clone())
    } else if interpreted
        || matches!(
            entry.kind,
            PayloadKind::ExtensionlessExecutable | PayloadKind::TextFile
        )
    {
        // The inventory entry does not retain its sniff window. Known closed
        // kinds still have a useful deterministic hint.
        Some(LanguageHint {
            language: match entry.kind {
                PayloadKind::Qml => "qml",
                PayloadKind::JavaScript => "javascript",
                PayloadKind::Shell => "shell",
                PayloadKind::Python => "python",
                _ => "unknown",
            }
            .to_owned(),
            confidence: "exact".to_owned(),
            source: "classification".to_owned(),
        })
    } else {
        None
    };
    let content_class = content_class_override
        .copied()
        .unwrap_or_else(|| content_class_for_entry(entry, native, interpreted));
    let (syntax_coverage, behavior_coverage) = match entry.kind {
        PayloadKind::Qml | PayloadKind::JavaScript => (
            if cfg!(feature = "qml-parser") {
                SyntaxCoverage::Parser
            } else {
                SyntaxCoverage::LexicalFallback
            },
            BehaviorCoverage::Bounded,
        ),
        PayloadKind::Python => (
            if cfg!(feature = "python-parser") {
                SyntaxCoverage::Parser
            } else {
                SyntaxCoverage::LexicalFallback
            },
            BehaviorCoverage::Partial,
        ),
        PayloadKind::Shell => (SyntaxCoverage::Bounded, BehaviorCoverage::Partial),
        PayloadKind::ElfBinary | PayloadKind::MachOBinary | PayloadKind::PeBinary => {
            (SyntaxCoverage::Bounded, BehaviorCoverage::Unsupported)
        }
        PayloadKind::Symlink | PayloadKind::Directory | PayloadKind::Special => {
            (SyntaxCoverage::Unavailable, BehaviorCoverage::Unavailable)
        }
        _ => (SyntaxCoverage::Unsupported, BehaviorCoverage::Unsupported),
    };
    let code_exposure = if entry.invocation_target {
        CodeExposure::KnownExecuteOrLoad
    } else if entry.executable || matches!(entry.kind, PayloadKind::ExtensionlessExecutable) {
        CodeExposure::EntryPoint
    } else if native.is_some() {
        CodeExposure::ExplicitlyUnreferenced
    } else if interpreted {
        CodeExposure::PossibleOrDynamic
    } else {
        CodeExposure::Unknown
    };
    let exact = (!entry.sampled_digest)
        .then(|| entry.sha256_sampled.clone())
        .flatten();
    let mut classification_evidence = Vec::new();
    if let Some(format) = native {
        classification_evidence.push(format!("native-magic:{format}"));
    } else if let Some(hint) = &hint {
        classification_evidence.push(format!("{}:{}", hint.source, hint.language));
    } else if entry.kind == PayloadKind::DataBinary {
        classification_evidence.push("nul-byte-sniff".to_owned());
    } else if entry.kind == PayloadKind::ExtensionlessExecutable || entry.executable {
        classification_evidence.push("execute-bit".to_owned());
    } else {
        classification_evidence.push("fallback-text".to_owned());
    }
    if entry.sampled_digest {
        classification_evidence.push("bounded-sample".to_owned());
    }
    let unsupported_text_script_reachable = matches!(entry.kind, PayloadKind::TextFile)
        && entry.invocation_target
        && hint.as_ref().is_some_and(|hint| hint.language != "unknown");
    PayloadCoverage {
        relative_path: entry.relative_path.clone(),
        inventory_state: if entry.coverage_state == CoverageState::Truncated
            || (entry.sha256_sampled.is_none()
                && !matches!(
                    entry.kind,
                    PayloadKind::Symlink | PayloadKind::Directory | PayloadKind::Special
                )) {
            InventoryState::Incomplete
        } else {
            InventoryState::Complete
        },
        language_hint: hint,
        syntax_coverage,
        behavior_coverage,
        code_exposure,
        content_class,
        exact_sha256: exact,
        digest_state: if entry.sampled_digest {
            "unavailable-sampled".to_owned()
        } else if entry.sha256_sampled.is_some() {
            "exact".to_owned()
        } else {
            "unavailable".to_owned()
        },
        native_format: native.map(str::to_owned),
        architecture: architecture.map(str::to_owned),
        classification_evidence,
        opaque_review_required: native.is_some()
            || matches!(
                content_class,
                ContentClass::ArchiveOrContainer | ContentClass::BytecodeOrWasm
            )
            || (matches!(entry.kind, PayloadKind::ExtensionlessExecutable)
                && (entry.executable || entry.invocation_target))
            || unsupported_text_script_reachable,
    }
}

fn content_class_for_entry(
    entry: &PayloadEntry,
    native: Option<&str>,
    interpreted: bool,
) -> ContentClass {
    let lower = entry.relative_path.to_ascii_lowercase();
    if is_archive_or_container_path(&lower) {
        return ContentClass::ArchiveOrContainer;
    }
    if is_bytecode_or_wasm_path(&lower) {
        return ContentClass::BytecodeOrWasm;
    }
    if native.is_some() {
        ContentClass::NativeCode
    } else if interpreted || matches!(entry.kind, PayloadKind::ExtensionlessExecutable) {
        ContentClass::InterpretedCode
    } else if matches!(entry.kind, PayloadKind::DataBinary) {
        ContentClass::OrdinaryData
    } else {
        ContentClass::Unknown
    }
}

/// Derive a typed content class from the bounded sniff prefix and path. The
/// legacy [`PayloadKind`] remains intentionally small; this orthogonal fact
/// keeps containers and bytecode from being mislabeled ordinary data.
pub fn content_class(path: &str, kind: &PayloadKind, prefix: &[u8]) -> ContentClass {
    let lower = path.to_ascii_lowercase();
    if is_archive_or_container_path(&lower) || archive_magic(prefix) {
        return ContentClass::ArchiveOrContainer;
    }
    if is_bytecode_or_wasm_path(&lower) || bytecode_magic(prefix) {
        return ContentClass::BytecodeOrWasm;
    }
    let native = native_format_for_kind(kind);
    let interpreted = matches!(
        kind,
        PayloadKind::Qml | PayloadKind::JavaScript | PayloadKind::Shell | PayloadKind::Python
    );
    content_class_for_entry(
        &PayloadEntry {
            relative_path: path.to_owned(),
            kind: kind.clone(),
            mode: 0,
            size: 0,
            sha256_sampled: None,
            sampled_digest: false,
            executable: false,
            coverage_state: CoverageState::Unsupported,
            link_target: None,
            invocation_target: false,
            object_id: None,
        },
        native,
        interpreted,
    )
}

fn archive_magic(prefix: &[u8]) -> bool {
    prefix.starts_with(b"PK\x03\x04")
        || prefix.starts_with(b"7z\xbc\xaf\x27\x1c")
        || prefix.starts_with(b"Rar!\x1a\x07")
        || prefix.starts_with(b"\x1f\x8b")
        || prefix.starts_with(b"BZh")
        || prefix.starts_with(b"\xfd7zXZ\x00")
        || prefix.starts_with(b"!<arch>\n")
        || prefix.get(257..262) == Some(b"ustar")
}

fn bytecode_magic(prefix: &[u8]) -> bool {
    prefix.starts_with(b"\0asm")
        || prefix.starts_with(b"\xca\xfe\xba\xbe")
        || prefix.starts_with(b"dex\n")
        || prefix.starts_with(b"BC\xc0\xde")
}

fn is_archive_or_container_path(path: &str) -> bool {
    [
        ".appimage",
        ".zip",
        ".tar",
        ".tgz",
        ".tar.gz",
        ".tbz",
        ".tbz2",
        ".tar.bz2",
        ".txz",
        ".tar.xz",
        ".7z",
        ".rar",
        ".jar",
        ".apk",
        ".deb",
        ".rpm",
        ".iso",
        ".cpio",
        ".cab",
    ]
    .iter()
    .any(|suffix| path.ends_with(suffix))
}

fn is_bytecode_or_wasm_path(path: &str) -> bool {
    [
        ".wasm", ".class", ".pyc", ".pyo", ".luac", ".beam", ".dex", ".bc",
    ]
    .iter()
    .any(|suffix| path.ends_with(suffix))
}

/// Bounded native-format architecture parsing. It reads only headers already
/// retained for classification and returns `unknown` for short/malformed
/// metadata; no loader or decoder is invoked.
pub fn native_architecture(kind: &PayloadKind, prefix: &[u8]) -> Option<String> {
    match kind {
        PayloadKind::ElfBinary => {
            let class = match prefix.get(4) {
                Some(1) => "32",
                Some(2) => "64",
                _ => return Some("unknown".to_owned()),
            };
            let little = match prefix.get(5) {
                Some(1) => true,
                Some(2) => false,
                _ => return Some("unknown".to_owned()),
            };
            let machine = read_u16(prefix.get(18..20)?, little);
            let name = match machine {
                3 => "x86",
                40 => "arm",
                62 => "x86-64",
                183 => "aarch64",
                243 => "riscv",
                _ => "unknown",
            };
            Some(format!(
                "{name}-{class}-{}",
                if little { "le" } else { "be" }
            ))
        }
        PayloadKind::MachOBinary => {
            let little = matches!(
                prefix.get(0..4),
                Some([0xcf, 0xfa, 0xed, 0xfe]) | Some([0xce, 0xfa, 0xed, 0xfe])
            );
            let cpu = read_u32(prefix.get(4..8)?, little);
            Some(
                match cpu {
                    7 => "x86-32",
                    0x0100_0007 => "x86-64",
                    12 => "arm",
                    0x0100_000c => "aarch64",
                    _ => "unknown",
                }
                .to_owned(),
            )
        }
        PayloadKind::PeBinary => {
            let offset = u32::from_le_bytes(
                prefix
                    .get(0x3c..0x40)
                    .and_then(|bytes| bytes.try_into().ok())
                    .unwrap_or([0, 0, 0, 0]),
            ) as usize;
            let machine = u16::from_le_bytes(
                prefix
                    .get(offset + 4..offset + 6)
                    .and_then(|bytes| bytes.try_into().ok())
                    .unwrap_or([0, 0]),
            );
            Some(
                match machine {
                    0x014c => "x86",
                    0x8664 => "x86-64",
                    0x01c0 | 0x01c4 => "arm",
                    0xaa64 => "aarch64",
                    _ => "unknown",
                }
                .to_owned(),
            )
        }
        _ => None,
    }
}

fn read_u16(bytes: &[u8], little: bool) -> u16 {
    if little {
        u16::from_le_bytes(bytes.try_into().unwrap_or([0, 0]))
    } else {
        u16::from_be_bytes(bytes.try_into().unwrap_or([0, 0]))
    }
}

fn read_u32(bytes: &[u8], little: bool) -> u32 {
    if little {
        u32::from_le_bytes(bytes.try_into().unwrap_or([0, 0, 0, 0]))
    } else {
        u32::from_be_bytes(bytes.try_into().unwrap_or([0, 0, 0, 0]))
    }
}

pub fn native_format_for_kind(kind: &PayloadKind) -> Option<&'static str> {
    match kind {
        PayloadKind::ElfBinary => Some("elf"),
        PayloadKind::MachOBinary => Some("macho"),
        PayloadKind::PeBinary => Some("pe"),
        _ => None,
    }
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
        assert_eq!(
            shebang_interpreter(b"#!/usr/bin/env -S python3 -u\n"),
            Some("python3".to_owned())
        );
        assert_eq!(
            shebang_interpreter(b"#!/bin/env -- python3\n"),
            Some("python3".to_owned())
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
    fn native_architecture_is_bounded_and_format_specific() {
        let mut elf = vec![0u8; 20];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[18..20].copy_from_slice(&62u16.to_le_bytes());
        assert_eq!(
            native_architecture(&PayloadKind::ElfBinary, &elf),
            Some("x86-64-64-le".to_owned())
        );
        assert_eq!(
            native_architecture(&PayloadKind::ElfBinary, b"\x7fELF"),
            Some("unknown".to_owned())
        );
        assert_eq!(native_architecture(&PayloadKind::TextFile, b""), None);
        assert_eq!(
            native_architecture(&PayloadKind::PeBinary, b"MZ"),
            Some("unknown".to_owned())
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

    #[test]
    fn language_hints_preserve_extension_and_shebang_conflicts() {
        let hint = language_hint("tool.py", b"#!/usr/bin/env ruby\nputs 1\n").unwrap();
        assert_eq!(hint.language, "python|ruby");
        assert_eq!(hint.confidence, "conflict");
        assert_eq!(hint.source, "extension-and-shebang");
    }

    #[test]
    fn opaque_content_classes_do_not_fall_through_to_ordinary_data() {
        assert_eq!(
            content_class("module.wasm", &PayloadKind::DataBinary, b""),
            ContentClass::BytecodeOrWasm
        );
        assert_eq!(
            content_class("bundle.bin", &PayloadKind::DataBinary, b"PK\x03\x04"),
            ContentClass::ArchiveOrContainer
        );
        let wasm = PayloadEntry {
            relative_path: "module.wasm".into(),
            kind: PayloadKind::DataBinary,
            mode: NON_EXEC,
            size: 4,
            sha256_sampled: Some("a".repeat(64)),
            sampled_digest: false,
            executable: false,
            coverage_state: CoverageState::Unsupported,
            link_target: None,
            invocation_target: false,
            object_id: None,
        };
        let coverage = payload_coverage(&wasm);
        assert_eq!(coverage.content_class, ContentClass::BytecodeOrWasm);
        assert!(coverage.opaque_review_required);
    }

    #[test]
    fn known_unsupported_text_script_requires_review_only_when_reachable() {
        let mut inventory = PayloadInventory {
            entries: vec![PayloadEntry {
                relative_path: "helper.fish".into(),
                kind: PayloadKind::TextFile,
                mode: NON_EXEC,
                size: 1,
                sha256_sampled: Some("a".repeat(64)),
                sampled_digest: false,
                executable: false,
                coverage_state: CoverageState::Unsupported,
                link_target: None,
                invocation_target: true,
                object_id: None,
            }],
            language_hints: BTreeMap::from([(
                "helper.fish".into(),
                LanguageHint {
                    language: "fish".into(),
                    confidence: "exact".into(),
                    source: "extension".into(),
                },
            )]),
            ..Default::default()
        };
        inventory.refresh_coverage();
        assert!(inventory.coverage[0].opaque_review_required);
        inventory.entries[0].invocation_target = false;
        inventory.refresh_coverage();
        assert!(!inventory.coverage[0].opaque_review_required);
    }
}
