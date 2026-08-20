use crate::{
    DetectedSource, Ecosystem, EnrichError, Package, ParseError, ProviderError, RegistryEnrichment,
    Vulnerability,
};
use async_trait::async_trait;
use std::{collections::HashMap, path::Path};

pub trait EcosystemParser: Send + Sync {
    fn ecosystem(&self) -> Ecosystem;
    fn detect(&self, dir: &Path) -> Vec<DetectedSource>;
    fn parse(&self, source: &DetectedSource) -> Result<Vec<Package>, ParseError>;
}

pub type VulnMap = HashMap<String, Vec<Vulnerability>>;

/// A vulnerability-provider result that can preserve trustworthy package results when another
/// package could not be enriched.
///
/// Keys in both maps are [`Package::key`] values. A package with an error must not be interpreted
/// as having a clean vulnerability result, even when its vulnerability vector is empty.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct VulnQueryOutcome {
    pub vulnerabilities: VulnMap,
    pub errors: HashMap<String, Vec<EnrichError>>,
}

impl VulnQueryOutcome {
    pub fn complete(vulnerabilities: VulnMap) -> Self {
        Self {
            vulnerabilities,
            errors: HashMap::new(),
        }
    }
}

#[async_trait]
pub trait VulnProvider: Send + Sync {
    async fn query(&self, packages: &[Package]) -> Result<VulnQueryOutcome, ProviderError>;
}
#[async_trait]
pub trait VersionProvider: Send + Sync {
    async fn latest(&self, package: &Package) -> Result<RegistryEnrichment, ProviderError>;
}
