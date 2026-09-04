//! Provenance for sources acquired for analysis.

use serde::Serialize;

pub const ACQUISITION_SCHEMA_VERSION: &str = "omasafe.acquisition.v1";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AcquisitionInputKind {
    RawGithubUrl,
    OmarchyInstallCommand,
    ExactGit,
    MarketplaceId,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AcquisitionOperation {
    ScanOnly,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InstallVerb {
    None,
    Add,
    Install,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResolvedIdentityKind {
    GitCommit,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum IntegrityState {
    ResolvedExact,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheResult {
    NotUsed,
    Hit,
    Miss,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolvedIdentity {
    pub kind: ResolvedIdentityKind,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Integrity {
    pub state: IntegrityState,
    pub algorithm: String,
    pub expected: Option<String>,
    pub observed: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CacheFact {
    pub used: bool,
    pub result: CacheResult,
}

#[derive(Debug, Clone, Serialize)]
pub struct AcquisitionSection {
    pub schema: &'static str,
    pub operation: AcquisitionOperation,
    pub installation_performed: bool,
    pub input_kind: AcquisitionInputKind,
    pub install_verb: InstallVerb,
    pub requested_reference: String,
    pub resolved_identity: ResolvedIdentity,
    pub integrity: Integrity,
    pub network_used: bool,
    pub cache: CacheFact,
    pub discarded_install_flags: Vec<String>,
    pub listed_repository: Option<String>,
    pub effective_repository_url: Option<String>,
    pub marketplace_claim: Option<serde_json::Value>,
    pub limitations: Vec<String>,
}

impl AcquisitionSection {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        input_kind: AcquisitionInputKind,
        install_verb: InstallVerb,
        requested_reference: impl Into<String>,
        repository_url: impl Into<String>,
        revision: impl Into<String>,
        network_used: bool,
        cache: CacheFact,
    ) -> Self {
        let revision = revision.into();
        let algorithm = if revision.len() == 64 {
            "git-sha256"
        } else {
            "git-sha1"
        };
        Self {
            schema: ACQUISITION_SCHEMA_VERSION,
            operation: AcquisitionOperation::ScanOnly,
            installation_performed: false,
            input_kind,
            install_verb,
            requested_reference: requested_reference.into(),
            resolved_identity: ResolvedIdentity {
                kind: ResolvedIdentityKind::GitCommit,
                value: revision.clone(),
            },
            integrity: Integrity {
                state: IntegrityState::ResolvedExact,
                algorithm: algorithm.into(),
                expected: None,
                observed: revision,
            },
            network_used,
            cache,
            discarded_install_flags: Vec::new(),
            listed_repository: None,
            effective_repository_url: Some(repository_url.into()),
            marketplace_claim: None,
            limitations: Vec::new(),
        }
    }
}
