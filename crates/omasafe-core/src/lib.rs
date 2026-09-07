pub mod bounds;
pub mod error;
pub mod git;
pub mod interrupt;
pub mod paths;
pub mod scan_snapshot;
pub mod source;
pub mod suppress;

pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const CORE_LOGIC_FINGERPRINT: &str = env!("CORE_LOGIC_FINGERPRINT");
