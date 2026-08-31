//! Test modules for the `detect` facade, split by behavior (plan A5 of
//! docs/detect-rs-maintenance-plan.md). The whole tree is compiled only in
//! test builds via the `#[cfg(test)] mod tests;` gate in `detect.rs`.

mod golden_tests;
mod h2_reference_tests;
mod h3_script_tests;
mod integration_tests;
mod round_fifteen_tests;
mod round_fourteen_tests;
mod round_seventeen_tests;
mod round_sixteen_tests;
mod round_thirteen_tests;
mod round_twelve_tests;
mod rule_contracts;
mod s4_boundary_tests;
pub(crate) mod s4_family_tests;
