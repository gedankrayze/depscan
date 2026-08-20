use super::*;

#[derive(Debug, Clone, Copy)]
pub struct OsvSyncOptions {
    /// Maximum wall-clock time for one dump transfer attempt.
    ///
    /// The HTTP client's ten-second connect/read-idle deadline still applies. A transfer may run
    /// longer than ten seconds while bytes continue to arrive, up to this overall deadline.
    pub transfer_timeout: StdDuration,
}

impl Default for OsvSyncOptions {
    fn default() -> Self {
        Self {
            transfer_timeout: OSV_DUMP_TRANSFER_TIMEOUT,
        }
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OsvSyncBoundary {
    AfterTemporaryCreation,
    BeforeValidation,
    BeforeRollbackStaging,
    BeforeArchivePublication,
    BeforeMarkerPublication,
    BeforeHandledErrorCleanup,
}

#[derive(Clone)]
pub(crate) struct OsvSyncConfig {
    pub(crate) base_url: String,
    pub(crate) transfer_timeout: StdDuration,
    pub(crate) max_download_bytes: u64,
    pub(crate) max_entry_bytes: u64,
    pub(crate) max_uncompressed_bytes: u64,
    pub(crate) max_entries: usize,
    pub(crate) attempts: usize,
    pub(crate) backoff_base: StdDuration,
    pub(crate) max_retry_delay: StdDuration,
    #[cfg(test)]
    pub(crate) boundary_hook: Option<Arc<dyn Fn(OsvSyncBoundary) + Send + Sync>>,
    #[cfg(test)]
    pub(crate) force_rollback_staging_error: bool,
    #[cfg(test)]
    pub(crate) observed_max_chunk_bytes: Option<Arc<std::sync::atomic::AtomicUsize>>,
    #[cfg(test)]
    pub(crate) stream_progress: Option<tokio::sync::watch::Sender<u64>>,
}

impl OsvSyncConfig {
    pub(crate) fn new(options: OsvSyncOptions) -> Result<Self, ProviderError> {
        if options.transfer_timeout.is_zero() {
            return Err(ProviderError::InvalidResponse(
                "OSV dump transfer timeout must be greater than zero".to_owned(),
            ));
        }
        Ok(Self {
            base_url: OSV_DUMP_BASE_URL.to_owned(),
            transfer_timeout: options.transfer_timeout,
            max_download_bytes: OSV_DUMP_MAX_DOWNLOAD_BYTES,
            max_entry_bytes: OSV_DUMP_MAX_ENTRY_BYTES,
            max_uncompressed_bytes: OSV_DUMP_MAX_UNCOMPRESSED_BYTES,
            max_entries: OSV_DUMP_MAX_ENTRIES,
            attempts: OSV_DUMP_ATTEMPTS,
            backoff_base: OSV_DUMP_BACKOFF_BASE,
            max_retry_delay: OSV_DUMP_MAX_RETRY_DELAY,
            #[cfg(test)]
            boundary_hook: None,
            #[cfg(test)]
            force_rollback_staging_error: false,
            #[cfg(test)]
            observed_max_chunk_bytes: None,
            #[cfg(test)]
            stream_progress: None,
        })
    }

    pub(crate) fn retry_settings(&self) -> RetrySettings {
        RetrySettings {
            attempts: self.attempts,
            backoff_base: self.backoff_base,
            max_delay: self.max_retry_delay,
        }
    }

    pub(crate) fn dump_limits(&self) -> OsvDumpLimits {
        OsvDumpLimits {
            max_compressed_bytes: self.max_download_bytes,
            max_entry_bytes: self.max_entry_bytes,
            max_uncompressed_bytes: self.max_uncompressed_bytes,
            max_entries: self.max_entries,
        }
    }

    #[cfg(test)]
    pub(crate) fn reach_boundary(&self, boundary: OsvSyncBoundary) {
        if let Some(hook) = &self.boundary_hook {
            hook(boundary);
        }
    }
}

#[derive(Debug)]
pub(crate) enum OsvDownloadFailure {
    Retryable {
        message: String,
        retry_after: Option<StdDuration>,
    },
    Fatal(ProviderError),
}

pub(crate) async fn stream_osv_dump_body<S, C, E, W>(
    mut chunks: S,
    destination: &mut W,
    url: &str,
    config: &OsvSyncConfig,
) -> Result<u64, OsvDownloadFailure>
where
    S: futures::Stream<Item = Result<C, E>> + Unpin,
    C: AsRef<[u8]>,
    E: std::fmt::Display,
    W: AsyncWrite + Unpin,
{
    let mut downloaded = 0u64;
    let mut next_progress = OSV_DUMP_PROGRESS_INTERVAL_BYTES;
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk.map_err(|error| OsvDownloadFailure::Retryable {
            message: format!("{url}: interrupted OSV dump transfer: {error}"),
            retry_after: None,
        })?;
        let bytes = chunk.as_ref();
        #[cfg(test)]
        if let Some(observed) = &config.observed_max_chunk_bytes {
            observed.fetch_max(bytes.len(), std::sync::atomic::Ordering::Relaxed);
        }
        downloaded = downloaded.checked_add(bytes.len() as u64).ok_or_else(|| {
            OsvDownloadFailure::Fatal(ProviderError::InvalidResponse(format!(
                "{url}: OSV dump size overflowed"
            )))
        })?;
        if downloaded > config.max_download_bytes {
            return Err(OsvDownloadFailure::Fatal(ProviderError::InvalidResponse(
                format!(
                    "{url}: OSV dump exceeds the {}-byte compressed-size limit",
                    config.max_download_bytes
                ),
            )));
        }
        destination
            .write_all(bytes)
            .await
            .map_err(|error| OsvDownloadFailure::Fatal(ProviderError::Cache(error.to_string())))?;
        #[cfg(test)]
        if let Some(progress) = &config.stream_progress {
            progress.send_replace(downloaded);
        }
        if downloaded >= next_progress {
            debug!(%url, downloaded, "streaming OSV dump");
            next_progress = downloaded.saturating_add(OSV_DUMP_PROGRESS_INTERVAL_BYTES);
        }
    }
    destination
        .flush()
        .await
        .map_err(|error| OsvDownloadFailure::Fatal(ProviderError::Cache(error.to_string())))?;
    Ok(downloaded)
}

impl HttpClient {
    pub(crate) async fn download_osv_dump_attempt(
        &self,
        url: &str,
        destination: &File,
        config: &OsvSyncConfig,
    ) -> Result<u64, OsvDownloadFailure> {
        let method = reqwest::Method::GET;
        let context = request_context(&method, url);
        let response = match self
            .inner
            .get(url)
            .timeout(config.transfer_timeout)
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                let message = match (error.is_timeout(), error.is_connect()) {
                    (true, _) => format!("{context}: request timed out"),
                    (_, true) => format!("{context}: connection failed"),
                    _ => format!("{context}: request failed"),
                };
                if retryable_transport(&error) {
                    return Err(OsvDownloadFailure::Retryable {
                        message,
                        retry_after: None,
                    });
                }
                return Err(OsvDownloadFailure::Fatal(ProviderError::Network(message)));
            }
        };
        let status = response.status();
        if retryable_status(status) {
            return Err(OsvDownloadFailure::Retryable {
                message: format!("{context}: HTTP {status}"),
                retry_after: retry_after_delay(
                    response.headers(),
                    self.retry_runtime.now(),
                    config.max_retry_delay,
                ),
            });
        }
        if !status.is_success() {
            return Err(OsvDownloadFailure::Fatal(ProviderError::Network(format!(
                "{context}: HTTP {status}"
            ))));
        }
        if response
            .content_length()
            .is_some_and(|length| length > config.max_download_bytes)
        {
            return Err(OsvDownloadFailure::Fatal(ProviderError::InvalidResponse(
                format!(
                    "{context}: OSV dump exceeds the {}-byte compressed-size limit",
                    config.max_download_bytes
                ),
            )));
        }

        let mut destination = destination
            .try_clone()
            .and_then(|mut file| {
                file.set_len(0)?;
                file.seek(SeekFrom::Start(0))?;
                Ok(file)
            })
            .map(tokio::fs::File::from_std)
            .map_err(|error| OsvDownloadFailure::Fatal(ProviderError::Cache(error.to_string())))?;
        let downloaded =
            stream_osv_dump_body(response.bytes_stream(), &mut destination, &context, config)
                .await?;
        destination
            .sync_all()
            .await
            .map_err(|error| OsvDownloadFailure::Fatal(ProviderError::Cache(error.to_string())))?;
        debug!(%url, downloaded, "OSV dump transfer complete");
        Ok(downloaded)
    }

    pub(crate) async fn download_osv_dump(
        &self,
        url: &str,
        destination: &File,
        config: &OsvSyncConfig,
    ) -> Result<u64, ProviderError> {
        let settings = config.retry_settings();
        for attempt_index in 0..settings.attempts {
            match self
                .download_osv_dump_attempt(url, destination, config)
                .await
            {
                Ok(downloaded) => return Ok(downloaded),
                Err(OsvDownloadFailure::Fatal(error)) => return Err(error),
                Err(OsvDownloadFailure::Retryable {
                    message,
                    retry_after,
                }) => {
                    if attempt_index + 1 < settings.attempts {
                        self.wait_before_retry(retry_after, attempt_index, settings)
                            .await;
                    } else {
                        return Err(ProviderError::Network(format!(
                            "{message} (attempt {}/{})",
                            attempt_index + 1,
                            settings.attempts
                        )));
                    }
                }
            }
        }
        Err(ProviderError::Network(format!(
            "{}: OSV dump transfer had no attempts",
            request_context(&reqwest::Method::GET, url)
        )))
    }
}
