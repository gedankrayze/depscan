use super::*;

#[derive(Debug, Clone, Copy)]
pub(crate) struct RetrySettings {
    pub(crate) attempts: usize,
    pub(crate) backoff_base: StdDuration,
    pub(crate) max_delay: StdDuration,
}

impl Default for RetrySettings {
    fn default() -> Self {
        Self {
            attempts: HTTP_ATTEMPTS,
            backoff_base: HTTP_BACKOFF_BASE,
            max_delay: HTTP_MAX_RETRY_DELAY,
        }
    }
}

#[async_trait]
pub(crate) trait RetryRuntime: Send + Sync {
    fn now(&self) -> SystemTime;
    fn jitter(&self, upper_bound: StdDuration) -> StdDuration;
    async fn sleep(&self, duration: StdDuration);
}

pub(crate) struct SystemRetryRuntime;

#[async_trait]
impl RetryRuntime for SystemRetryRuntime {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }

    fn jitter(&self, upper_bound: StdDuration) -> StdDuration {
        let upper_millis = u64::try_from(upper_bound.as_millis()).unwrap_or(u64::MAX);
        StdDuration::from_millis(rand::rng().random_range(0..=upper_millis))
    }

    async fn sleep(&self, duration: StdDuration) {
        sleep(duration).await;
    }
}

pub(crate) fn retryable_status(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

pub(crate) fn retryable_transport(error: &reqwest::Error) -> bool {
    error.is_connect() || error.is_timeout()
}

pub(crate) fn request_context(method: &reqwest::Method, url: &str) -> String {
    let Ok(mut sanitized) = reqwest::Url::parse(url) else {
        return format!("{method} <invalid URL>");
    };
    let _ = sanitized.set_username("");
    let _ = sanitized.set_password(None);
    sanitized.set_query(None);
    sanitized.set_fragment(None);
    format!("{method} {sanitized}")
}

pub(crate) fn network_attempt_error(
    context: &str,
    detail: &str,
    attempt: usize,
    attempts: usize,
) -> ProviderError {
    ProviderError::Network(format!(
        "{context}: {detail} (attempt {attempt}/{attempts})"
    ))
}

pub(crate) fn transport_attempt_error(
    context: &str,
    error: &reqwest::Error,
    attempt: usize,
    attempts: usize,
) -> ProviderError {
    let detail = if error.is_timeout() {
        "request timed out"
    } else if error.is_connect() {
        "connection failed"
    } else if error.is_builder() {
        "request could not be built"
    } else {
        "request failed"
    };
    network_attempt_error(context, detail, attempt, attempts)
}

pub(crate) fn retry_after_delay(
    headers: &HeaderMap,
    now: SystemTime,
    cap: StdDuration,
) -> Option<StdDuration> {
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();
    let delay = if let Ok(seconds) = value.parse::<u64>() {
        StdDuration::from_secs(seconds)
    } else {
        httpdate::parse_http_date(value)
            .ok()?
            .duration_since(now)
            .unwrap_or(StdDuration::ZERO)
    };
    Some(std::cmp::min(delay, cap))
}

pub(crate) fn retry_backoff(
    settings: RetrySettings,
    retry_index: usize,
    runtime: &dyn RetryRuntime,
) -> StdDuration {
    let multiplier = 1u32
        .checked_shl(retry_index.min(31) as u32)
        .unwrap_or(u32::MAX);
    let base = std::cmp::min(
        settings.backoff_base.saturating_mul(multiplier),
        settings.max_delay,
    );
    let jitter_bound_millis = u64::try_from(base.as_millis() / 4).unwrap_or(u64::MAX);
    let jitter_bound = std::cmp::min(
        StdDuration::from_millis(jitter_bound_millis),
        settings.max_delay.saturating_sub(base),
    );
    let jitter = std::cmp::min(runtime.jitter(jitter_bound), jitter_bound);
    base.saturating_add(jitter)
}
