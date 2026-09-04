pub mod bounds;
pub mod error;
pub mod git;
pub mod interrupt;
pub mod paths;
pub mod source;
pub mod suppress;

pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
