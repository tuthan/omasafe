use serde::Serialize;

#[derive(Debug, Default, Serialize)]
pub struct Inventory {
    pub plugins: Vec<PluginRecord>,
    pub coverage: Coverage,
}

#[derive(Debug, Serialize)]
pub struct PluginRecord {
    pub id: String,
    pub path: String,
    pub classification: String,
}

#[derive(Debug, Default, Serialize)]
pub struct Coverage {
    pub limitations: Vec<String>,
}
