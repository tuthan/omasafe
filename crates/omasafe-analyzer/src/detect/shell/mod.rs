//! Shell analysis layers extracted from `detect.rs` (Stage A of
//! docs/detect-rs-maintenance-plan.md). Visibility is scoped to the
//! `detect` module; nothing here is public API.

pub(in crate::detect) mod budget;
pub(in crate::detect) mod command;
pub(in crate::detect) mod interpreter;
pub(in crate::detect) mod lexer;
pub(in crate::detect) mod source;
pub(in crate::detect) mod syntax;
