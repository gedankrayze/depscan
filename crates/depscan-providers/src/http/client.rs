use super::*;

#[derive(Clone)]
pub struct HttpClient {
    pub(crate) inner: Client,
    pub(crate) request_timeout: StdDuration,
    pub(crate) max_json_bytes: usize,
    pub(crate) retry_runtime: Arc<dyn RetryRuntime>,
    pub(crate) retry_settings: RetrySettings,
}
impl std::fmt::Debug for HttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpClient")
            .field("request_timeout", &self.request_timeout)
            .field("max_json_bytes", &self.max_json_bytes)
            .field("retry_settings", &self.retry_settings)
            .finish_non_exhaustive()
    }
}

impl HttpClient {
    pub fn new() -> Result<Self, ProviderError> {
        Self::with_timeouts(HTTP_REQUEST_TIMEOUT, HTTP_REQUEST_TIMEOUT)
    }

    pub(crate) fn with_timeouts(
        request_timeout: StdDuration,
        network_idle_timeout: StdDuration,
    ) -> Result<Self, ProviderError> {
        Self::with_retry_runtime(
            request_timeout,
            network_idle_timeout,
            RetrySettings::default(),
            Arc::new(SystemRetryRuntime),
        )
    }

    pub(crate) fn with_retry_runtime(
        request_timeout: StdDuration,
        network_idle_timeout: StdDuration,
        retry_settings: RetrySettings,
        retry_runtime: Arc<dyn RetryRuntime>,
    ) -> Result<Self, ProviderError> {
        let client = Client::builder()
            .user_agent(USER_AGENT_VALUE)
            .connect_timeout(network_idle_timeout)
            .read_timeout(network_idle_timeout)
            .gzip(true)
            .http2_adaptive_window(true)
            .build()
            .map_err(|e| ProviderError::Network(e.to_string()))?;
        Ok(Self {
            inner: client,
            request_timeout,
            max_json_bytes: HTTP_MAX_JSON_RESPONSE_BYTES,
            retry_runtime,
            retry_settings,
        })
    }

    pub(crate) async fn wait_before_retry(
        &self,
        retry_after: Option<StdDuration>,
        retry_index: usize,
        settings: RetrySettings,
    ) {
        let delay = retry_after
            .unwrap_or_else(|| retry_backoff(settings, retry_index, self.retry_runtime.as_ref()));
        self.retry_runtime.sleep(delay).await;
    }

    pub(crate) async fn request_json(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<Value>,
        headers: HeaderMap,
    ) -> Result<Revalidated<Value>, ProviderError> {
        let settings = self.retry_settings;
        let context = request_context(&method, url);
        for attempt_index in 0..settings.attempts {
            let attempt = attempt_index + 1;
            let mut request = self
                .inner
                .request(method.clone(), url)
                .headers(headers.clone())
                .timeout(self.request_timeout);
            if let Some(body) = &body {
                request = request.json(body);
            }
            match request.send().await {
                Ok(response) if response.status() == StatusCode::NOT_MODIFIED => {
                    let etag = response
                        .headers()
                        .get(ETAG)
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_owned);
                    return Ok(Revalidated::NotModified { etag });
                }
                Ok(response) if response.status().is_success() => {
                    let etag = response
                        .headers()
                        .get(ETAG)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned);
                    match read_body(response, self.max_json_bytes).await {
                        Ok(bytes) => {
                            let value = serde_json::from_slice(&bytes).map_err(|_| {
                                ProviderError::InvalidResponse(format!(
                                    "{context}: invalid JSON response"
                                ))
                            })?;
                            return Ok(Revalidated::Modified { value, etag });
                        }
                        Err(BodyError::Transport(error)) => {
                            let final_error = transport_attempt_error(
                                &context,
                                &error,
                                attempt,
                                settings.attempts,
                            );
                            if !retryable_transport(&error) || attempt == settings.attempts {
                                return Err(final_error);
                            }
                            self.wait_before_retry(None, attempt_index, settings).await;
                        }
                        Err(BodyError::TooLarge) => {
                            return Err(ProviderError::InvalidResponse(format!(
                                "{context}: response exceeds the {}-byte limit",
                                self.max_json_bytes
                            )));
                        }
                    }
                }
                Ok(response) => {
                    let status = response.status();
                    let final_error = network_attempt_error(
                        &context,
                        &format!("HTTP {status}"),
                        attempt,
                        settings.attempts,
                    );
                    if !retryable_status(status) || attempt == settings.attempts {
                        return Err(final_error);
                    }
                    let retry_after = retry_after_delay(
                        response.headers(),
                        self.retry_runtime.now(),
                        settings.max_delay,
                    );
                    self.wait_before_retry(retry_after, attempt_index, settings)
                        .await;
                }
                Err(error) => {
                    let final_error =
                        transport_attempt_error(&context, &error, attempt, settings.attempts);
                    if !retryable_transport(&error) || attempt == settings.attempts {
                        return Err(final_error);
                    }
                    self.wait_before_retry(None, attempt_index, settings).await;
                }
            }
        }
        Err(ProviderError::Network(format!(
            "{context}: retry policy allowed no attempts"
        )))
    }
    pub(crate) async fn get_json(
        &self,
        url: &str,
        headers: HeaderMap,
    ) -> Result<(Value, Option<String>), ProviderError> {
        match self
            .request_json(reqwest::Method::GET, url, None, headers)
            .await?
        {
            Revalidated::Modified { value, etag } => Ok((value, etag)),
            Revalidated::NotModified { .. } => Err(ProviderError::InvalidResponse(format!(
                "{url}: received HTTP 304 without a conditional cache request"
            ))),
        }
    }
    pub(crate) async fn get_json_revalidated(
        &self,
        url: &str,
        headers: HeaderMap,
    ) -> Result<Revalidated<Value>, ProviderError> {
        self.request_json(reqwest::Method::GET, url, None, headers)
            .await
    }
    pub(crate) async fn post_json(&self, url: &str, body: Value) -> Result<Value, ProviderError> {
        match self
            .request_json(reqwest::Method::POST, url, Some(body), HeaderMap::new())
            .await?
        {
            Revalidated::Modified { value, .. } => Ok(value),
            Revalidated::NotModified { .. } => Err(ProviderError::InvalidResponse(format!(
                "{url}: received HTTP 304 for a POST request"
            ))),
        }
    }
    pub(crate) async fn get_bytes_limited_revalidated(
        &self,
        url: &str,
        max_bytes: usize,
        headers: HeaderMap,
    ) -> Result<Revalidated<Vec<u8>>, ProviderError> {
        let settings = self.retry_settings;
        let method = reqwest::Method::GET;
        let context = request_context(&method, url);
        for attempt_index in 0..settings.attempts {
            let attempt = attempt_index + 1;
            let response = match self
                .inner
                .get(url)
                .headers(headers.clone())
                .timeout(self.request_timeout)
                .send()
                .await
            {
                Ok(response) => response,
                Err(error) => {
                    let final_error =
                        transport_attempt_error(&context, &error, attempt, settings.attempts);
                    if !retryable_transport(&error) || attempt == settings.attempts {
                        return Err(final_error);
                    }
                    self.wait_before_retry(None, attempt_index, settings).await;
                    continue;
                }
            };
            let etag = response
                .headers()
                .get(ETAG)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            if response.status() == StatusCode::NOT_MODIFIED {
                return Ok(Revalidated::NotModified { etag });
            }
            let status = response.status();
            if !status.is_success() {
                let final_error = network_attempt_error(
                    &context,
                    &format!("HTTP {status}"),
                    attempt,
                    settings.attempts,
                );
                if !retryable_status(status) || attempt == settings.attempts {
                    return Err(final_error);
                }
                let retry_after = retry_after_delay(
                    response.headers(),
                    self.retry_runtime.now(),
                    settings.max_delay,
                );
                self.wait_before_retry(retry_after, attempt_index, settings)
                    .await;
                continue;
            }
            match read_body(response, max_bytes).await {
                Ok(bytes) => return Ok(Revalidated::Modified { value: bytes, etag }),
                Err(BodyError::TooLarge) => {
                    return Err(ProviderError::InvalidResponse(format!(
                        "{context}: response exceeds the {max_bytes}-byte limit"
                    )));
                }
                Err(BodyError::Transport(error)) => {
                    let final_error =
                        transport_attempt_error(&context, &error, attempt, settings.attempts);
                    if !retryable_transport(&error) || attempt == settings.attempts {
                        return Err(final_error);
                    }
                    self.wait_before_retry(None, attempt_index, settings).await;
                }
            }
        }
        Err(ProviderError::Network(format!(
            "{context}: retry policy allowed no attempts"
        )))
    }

    pub(crate) async fn get_json_limited_revalidated(
        &self,
        url: &str,
        max_bytes: usize,
        headers: HeaderMap,
    ) -> Result<Revalidated<Value>, ProviderError> {
        match self
            .get_bytes_limited_revalidated(url, max_bytes, headers)
            .await?
        {
            Revalidated::Modified { value, etag } => {
                let value = serde_json::from_slice(&value).map_err(|_| {
                    ProviderError::InvalidResponse(format!("GET {url}: invalid JSON response"))
                })?;
                Ok(Revalidated::Modified { value, etag })
            }
            Revalidated::NotModified { etag } => Ok(Revalidated::NotModified { etag }),
        }
    }
}
