use super::*;

pub(crate) enum RawResponseBody {
    Fixed(Vec<u8>),
    Truncated {
        body: Vec<u8>,
        bytes_to_send: usize,
    },
    Chunked {
        body: Vec<u8>,
        chunk_size: usize,
        delay: StdDuration,
        pause_after_chunks: Option<usize>,
        paused: Option<Arc<Notify>>,
        resume: Option<Arc<Notify>>,
    },
}

pub(crate) struct RawResponse {
    pub(crate) status: u16,
    pub(crate) retry_after: Option<String>,
    pub(crate) body: RawResponseBody,
}

impl RawResponse {
    pub(crate) fn fixed(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            retry_after: None,
            body: RawResponseBody::Fixed(body),
        }
    }

    pub(crate) fn truncated(body: Vec<u8>, bytes_to_send: usize) -> Self {
        Self {
            status: 200,
            retry_after: None,
            body: RawResponseBody::Truncated {
                body,
                bytes_to_send,
            },
        }
    }
}

pub(crate) async fn read_raw_request(stream: &mut TcpStream) -> std::io::Result<()> {
    let mut request = Vec::new();
    let mut buffer = [0u8; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if request.len() > 64 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "test request headers are too large",
            ));
        }
    }
    Ok(())
}

pub(crate) async fn write_raw_response(
    stream: &mut TcpStream,
    response: RawResponse,
) -> std::io::Result<()> {
    let reason = match response.status {
        200 => "OK",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "Test Response",
    };
    let retry_after = response
        .retry_after
        .map(|value| format!("Retry-After: {value}\r\n"))
        .unwrap_or_default();
    match response.body {
        RawResponseBody::Fixed(body) => {
            let headers = format!(
                "HTTP/1.1 {} {}\r\nConnection: close\r\n{}Content-Length: {}\r\n\r\n",
                response.status,
                reason,
                retry_after,
                body.len()
            );
            stream.write_all(headers.as_bytes()).await?;
            stream.write_all(&body).await?;
        }
        RawResponseBody::Truncated {
            body,
            bytes_to_send,
        } => {
            let headers = format!(
                "HTTP/1.1 {} {}\r\nConnection: close\r\n{}Content-Length: {}\r\n\r\n",
                response.status,
                reason,
                retry_after,
                body.len()
            );
            stream.write_all(headers.as_bytes()).await?;
            stream
                .write_all(&body[..bytes_to_send.min(body.len())])
                .await?;
        }
        RawResponseBody::Chunked {
            body,
            chunk_size,
            delay,
            pause_after_chunks,
            paused,
            resume,
        } => {
            let headers = format!(
                "HTTP/1.1 {} {}\r\nConnection: close\r\n{}Transfer-Encoding: chunked\r\n\r\n",
                response.status, reason, retry_after
            );
            stream.write_all(headers.as_bytes()).await?;
            for (index, chunk) in body.chunks(chunk_size).enumerate() {
                stream
                    .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                    .await?;
                stream.write_all(chunk).await?;
                stream.write_all(b"\r\n").await?;
                stream.flush().await?;
                if pause_after_chunks == Some(index + 1) {
                    if let Some(paused) = &paused {
                        paused.notify_one();
                    }
                    if let Some(resume) = &resume {
                        resume.notified().await;
                    }
                }
                sleep(delay).await;
            }
            stream.write_all(b"0\r\n\r\n").await?;
        }
    }
    stream.flush().await
}

pub(crate) async fn spawn_raw_server(
    responses: Vec<RawResponse>,
) -> (String, Arc<AtomicUsize>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let server_requests = requests.clone();
    let handle = tokio::spawn(async move {
        for response in responses {
            let (mut stream, _) = listener.accept().await.unwrap();
            server_requests.fetch_add(1, Ordering::SeqCst);
            if read_raw_request(&mut stream).await.is_ok() {
                let _ = write_raw_response(&mut stream, response).await;
            }
        }
    });
    (format!("http://{address}"), requests, handle)
}

pub(crate) struct RecordingRetryRuntime {
    now: SystemTime,
    sleeps: Mutex<Vec<StdDuration>>,
    jitter_bounds: Mutex<Vec<StdDuration>>,
}

impl RecordingRetryRuntime {
    pub(crate) fn new(now: SystemTime) -> Self {
        Self {
            now,
            sleeps: Mutex::new(Vec::new()),
            jitter_bounds: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn sleeps(&self) -> Vec<StdDuration> {
        self.sleeps.lock().unwrap().clone()
    }

    pub(crate) fn jitter_bounds(&self) -> Vec<StdDuration> {
        self.jitter_bounds.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl RetryRuntime for RecordingRetryRuntime {
    fn now(&self) -> SystemTime {
        self.now
    }

    fn jitter(&self, upper_bound: StdDuration) -> StdDuration {
        self.jitter_bounds.lock().unwrap().push(upper_bound);
        StdDuration::ZERO
    }

    async fn sleep(&self, duration: StdDuration) {
        self.sleeps.lock().unwrap().push(duration);
    }
}

pub(crate) fn test_http_client(
    runtime: Arc<RecordingRetryRuntime>,
    request_timeout: StdDuration,
) -> HttpClient {
    HttpClient::with_retry_runtime(
        request_timeout,
        request_timeout,
        RetrySettings::default(),
        runtime,
    )
    .unwrap()
}
