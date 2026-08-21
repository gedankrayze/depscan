use super::sync::{OfflineDirectory, visit_osv_dump_file};
use super::*;

#[derive(Debug, Clone, Copy)]
pub(crate) struct OsvDumpLimits {
    pub(crate) max_compressed_bytes: u64,
    pub(crate) max_entry_bytes: u64,
    pub(crate) max_uncompressed_bytes: u64,
    pub(crate) max_entries: usize,
}

impl OsvDumpLimits {
    pub(crate) fn production() -> Self {
        Self {
            max_compressed_bytes: OSV_DUMP_MAX_DOWNLOAD_BYTES,
            max_entry_bytes: OSV_DUMP_MAX_ENTRY_BYTES,
            max_uncompressed_bytes: OSV_DUMP_MAX_UNCOMPRESSED_BYTES,
            max_entries: OSV_DUMP_MAX_ENTRIES,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum OsvDumpValidationContext<'a> {
    Sync(Ecosystem),
    Offline(&'a Path),
}

impl OsvDumpValidationContext<'_> {
    pub(crate) fn invalid(self, reason: impl std::fmt::Display) -> ProviderError {
        match self {
            Self::Sync(ecosystem) => ProviderError::InvalidResponse(format!(
                "OSV dump for {} is invalid: {reason}",
                ecosystem.osv_name()
            )),
            Self::Offline(path) => {
                ProviderError::Offline(format!("OSV dump {} is invalid: {reason}", path.display()))
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct OsvOffline {
    pub(crate) cache: Cache,
    pub(crate) limits: OsvDumpLimits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OsvDumpAge {
    Current,
    Warn {
        synced_at: DateTime<Utc>,
        age: Duration,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OsvOfflineReadBoundary {
    BeforeMarker,
    BeforeArchive,
    AfterArchive,
}

pub(crate) struct OfflineDumpRead {
    pub(crate) archive: File,
    pub(crate) marker: File,
    pub(crate) archive_name: OsString,
    pub(crate) marker_name: OsString,
    pub(crate) archive_path: PathBuf,
    pub(crate) marker_path: PathBuf,
    pub(crate) archive_identity: FileIdentity,
    pub(crate) marker_identity: FileIdentity,
}

pub(crate) fn offline_capability_error(error: ProviderError) -> ProviderError {
    ProviderError::Offline(error.to_string())
}

impl OsvOffline {
    pub fn new(cache: Cache) -> Self {
        Self {
            cache,
            limits: OsvDumpLimits::production(),
        }
    }
    pub(crate) fn validate_dump_age_from_file(
        &self,
        archive_path: &Path,
        marker_path: &Path,
        marker: &mut File,
        ecosystem: Ecosystem,
        now: DateTime<Utc>,
    ) -> Result<OsvDumpAge, ProviderError> {
        marker.rewind().map_err(|error| {
            ProviderError::Offline(format!(
                "cannot seek OSV dump timestamp {}: {error}",
                marker_path.display()
            ))
        })?;
        let mut raw = String::new();
        marker.read_to_string(&mut raw).map_err(|error| {
            ProviderError::Offline(format!(
                "cannot read OSV dump timestamp {}: {error}",
                marker_path.display()
            ))
        })?;
        let synced_at = DateTime::parse_from_rfc3339(raw.trim())
            .map(|timestamp| timestamp.with_timezone(&Utc))
            .map_err(|error| {
                ProviderError::Offline(format!(
                    "invalid OSV dump timestamp {}: {error}; run `depscan sync --ecosystem {}`",
                    marker_path.display(),
                    ecosystem.display_name()
                ))
            })?;
        if synced_at > now {
            return Err(ProviderError::Offline(format!(
                "OSV dump timestamp {} is in the future ({synced_at} > {now}); run `depscan sync --ecosystem {}`",
                marker_path.display(),
                ecosystem.display_name()
            )));
        }
        let age = now - synced_at;
        if let Some(max_age) = self.cache.policy.max_age {
            if age > max_age {
                return Err(ProviderError::Offline(format!(
                    "OSV dump {} is stale: its age of {} seconds exceeds --max-cache-age ({} seconds); run `depscan sync --ecosystem {}`",
                    archive_path.display(),
                    age.num_seconds(),
                    max_age.num_seconds(),
                    ecosystem.display_name()
                )));
            }
            return Ok(OsvDumpAge::Current);
        }
        if age > Duration::seconds(OSV_DUMP_DEFAULT_WARNING_AGE_SECS) {
            Ok(OsvDumpAge::Warn { synced_at, age })
        } else {
            Ok(OsvDumpAge::Current)
        }
    }

    #[cfg(test)]
    pub(crate) fn validate_dump_age_at(
        &self,
        archive_path: &Path,
        ecosystem: Ecosystem,
        now: DateTime<Utc>,
    ) -> Result<OsvDumpAge, ProviderError> {
        let directory =
            OfflineDirectory::open(self.cache.root()).map_err(offline_capability_error)?;
        let mut dump = directory.open_dump(ecosystem)?;
        debug_assert_eq!(dump.archive_path, archive_path);
        self.validate_dump_age_from_file(
            &dump.archive_path,
            &dump.marker_path,
            &mut dump.marker,
            ecosystem,
            now,
        )
    }

    pub(crate) fn query_blocking_at(
        &self,
        packages: &[Package],
        now: DateTime<Utc>,
    ) -> Result<VulnMap, ProviderError> {
        self.query_blocking_at_with_hook(packages, now, |_| {})
    }

    pub(crate) fn query_blocking_at_with_hook<F>(
        &self,
        packages: &[Package],
        now: DateTime<Utc>,
        hook: F,
    ) -> Result<VulnMap, ProviderError>
    where
        F: Fn(OsvOfflineReadBoundary),
    {
        let mut output = VulnMap::new();
        for package in packages {
            output.entry(package.key()).or_default();
        }
        let mut offline_directory = None;
        for ecosystem in [
            Ecosystem::Npm,
            Ecosystem::PyPI,
            Ecosystem::NuGet,
            Ecosystem::CratesIo,
        ] {
            let scoped: Vec<_> = packages
                .iter()
                .filter(|p| p.ecosystem == ecosystem && p.enrichable && !p.resolved_from_range)
                .collect();
            if scoped.is_empty() {
                continue;
            }
            if offline_directory.is_none() {
                offline_directory = Some(
                    OfflineDirectory::open(self.cache.root()).map_err(offline_capability_error)?,
                );
            }
            let directory = offline_directory
                .as_ref()
                .expect("offline directory is opened for a scoped ecosystem");
            let mut dump = directory.open_dump(ecosystem)?;
            hook(OsvOfflineReadBoundary::BeforeMarker);
            if let OsvDumpAge::Warn { synced_at, age } = self.validate_dump_age_from_file(
                &dump.archive_path,
                &dump.marker_path,
                &mut dump.marker,
                ecosystem,
                now,
            )? {
                warn!(
                    ecosystem = ecosystem.osv_name(),
                    path = %dump.archive_path.display(),
                    %synced_at,
                    age_seconds = age.num_seconds(),
                    warning_age_seconds = OSV_DUMP_DEFAULT_WARNING_AGE_SECS,
                    "OSV dump is older than the default seven-day warning age; run `depscan sync`"
                );
            }
            hook(OsvOfflineReadBoundary::BeforeArchive);
            let archive = dump
                .archive
                .try_clone()
                .map_err(|error| ProviderError::Offline(error.to_string()))?;
            let context = OsvDumpValidationContext::Offline(&dump.archive_path);
            visit_osv_dump_file(
                archive,
                context,
                self.limits,
                true,
                |entry_name, document, validated| {
                    for package in &scoped {
                        if let Some(vulnerability) = vulnerability_from_validated_osv(
                            document,
                            validated,
                            Some(package),
                            false,
                        )
                        .map_err(|error| {
                            context.invalid(format_args!(
                                "entry {entry_name:?} cannot be evaluated: {error}"
                            ))
                        })? {
                            output.entry(package.key()).or_default().push(vulnerability);
                        }
                    }
                    Ok(())
                },
            )?;
            hook(OsvOfflineReadBoundary::AfterArchive);
            directory.revalidate_dump(&dump)?;
        }
        Ok(output)
    }

    pub(crate) fn query_blocking(&self, packages: &[Package]) -> Result<VulnMap, ProviderError> {
        self.query_blocking_at(packages, Utc::now())
    }
}
#[async_trait]
impl VulnProvider for OsvOffline {
    async fn query(&self, packages: &[Package]) -> Result<VulnQueryOutcome, ProviderError> {
        let this = self.clone();
        let owned = packages.to_vec();
        let vulnerabilities = tokio::task::spawn_blocking(move || this.query_blocking(&owned))
            .await
            .map_err(|e| ProviderError::Offline(e.to_string()))??;
        Ok(VulnQueryOutcome::complete(vulnerabilities))
    }
}
