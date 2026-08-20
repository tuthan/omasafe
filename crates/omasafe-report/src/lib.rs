use serde::Serialize;

pub const SCHEMA_VERSION: &str = "omasafe.report.v1";

#[derive(Debug, Serialize)]
pub struct Report<T> {
    pub schema: &'static str,
    pub tool_version: &'static str,
    pub generated_at: String,
    pub result: T,
}

impl<T> Report<T> {
    pub fn new(tool_version: &'static str, generated_at: String, result: T) -> Self {
        Self {
            schema: SCHEMA_VERSION,
            tool_version,
            generated_at,
            result,
        }
    }
}
