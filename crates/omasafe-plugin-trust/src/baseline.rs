use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::SourceIdentity;

pub const HISTORY_SCHEMA_VERSION: u64 = 1;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("trust history I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("trust history is malformed: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TrustHistory {
    pub schema_version: u64,
    pub records: Vec<TrustRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrustRecord {
    pub plugin_id: String,
    pub accepted: SourceIdentity,
    pub accepted_at: String,
    pub note: String,
}

impl TrustHistory {
    pub fn load(path: &Path) -> Result<Self, Error> {
        if !path.exists() {
            return Ok(Self {
                schema_version: HISTORY_SCHEMA_VERSION,
                records: Vec::new(),
            });
        }
        let history = serde_json::from_slice(&fs::read(path)?)?;
        Ok(history)
    }

    pub fn accept(&mut self, record: TrustRecord) {
        self.schema_version = HISTORY_SCHEMA_VERSION;
        self.records.push(record);
    }

    pub fn latest(&self, plugin_id: &str) -> Option<&TrustRecord> {
        self.records
            .iter()
            .rev()
            .find(|record| record.plugin_id == plugin_id)
    }

    pub fn write_atomic(&self, path: &Path) -> Result<(), Error> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
        fs::write(&temporary, serde_json::to_vec_pretty(self)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
        }
        fs::rename(temporary, path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_round_trips_and_keeps_previous_trust() {
        let path = std::env::temp_dir().join(format!("omasafe-trust-{}.json", std::process::id()));
        let identity = SourceIdentity {
            plugin_id: "io.example.test".into(),
            repository: None,
            head: Some("head".into()),
            tree: Some("tree".into()),
            content_digest: Some("digest".into()),
            file_count: 1,
            limitations: Vec::new(),
        };
        let mut history = TrustHistory::default();
        history.accept(TrustRecord {
            plugin_id: identity.plugin_id.clone(),
            accepted: identity.clone(),
            accepted_at: "first".into(),
            note: "first trust".into(),
        });
        history.write_atomic(&path).unwrap();
        let loaded = TrustHistory::load(&path).unwrap();
        assert_eq!(
            loaded.latest("io.example.test").unwrap().accepted_at,
            "first"
        );
        let _ = std::fs::remove_file(path);
    }
}
