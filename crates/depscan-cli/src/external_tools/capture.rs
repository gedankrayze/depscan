use super::*;

pub(super) async fn run(request: ToolRequest) -> Result<ToolOutput, ToolError> {
    let (executable, sanitized_path) = resolve_executable(request.tool, &request)?;
    let tool_home = tempfile::Builder::new()
        .prefix("depscan-tool-")
        .tempdir()
        .map_err(|error| ToolError::Setup {
            tool: request.tool,
            path: request.path.clone(),
            message: format!("cannot create temporary home: {error}"),
        })?;

    let mut command = Command::new(executable);
    command
        .args(&request.arguments)
        .current_dir(&request.working_directory)
        .env_clear()
        .env("PATH", sanitized_path)
        .env("HOME", tool_home.path())
        .env("USERPROFILE", tool_home.path())
        .env("TMPDIR", tool_home.path())
        .env("TMP", tool_home.path())
        .env("TEMP", tool_home.path())
        .env("CI", "1")
        .env("NO_COLOR", "1")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .env("DOTNET_CLI_HOME", tool_home.path())
        .env("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
        .env("DOTNET_NOLOGO", "1")
        .env("DOTNET_SKIP_FIRST_TIME_EXPERIENCE", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = command.spawn().map_err(|error| ToolError::Spawn {
        tool: request.tool,
        path: request.path.clone(),
        message: error.to_string(),
        hint: request.hint,
    })?;
    capture_child(&mut child, &request, &tool_home).await
}

async fn capture_child(
    child: &mut Child,
    request: &ToolRequest,
    _tool_home: &TempDir,
) -> Result<ToolOutput, ToolError> {
    let stdout = child.stdout.take().ok_or_else(|| ToolError::Capture {
        tool: request.tool,
        path: request.path.clone(),
        stream: "stdout",
        message: "stdout pipe was unavailable".to_owned(),
        hint: request.hint,
    })?;
    let stderr = child.stderr.take().ok_or_else(|| ToolError::Capture {
        tool: request.tool,
        path: request.path.clone(),
        stream: "stderr",
        message: "stderr pipe was unavailable".to_owned(),
        hint: request.hint,
    })?;

    let capture = async {
        let wait = async { child.wait().await.map_err(CaptureError::Wait) };
        let output = async {
            let (stdout, stderr) = tokio::try_join!(
                read_limited(stdout, "stdout", STDOUT_LIMIT),
                read_limited(stderr, "stderr", STDERR_LIMIT)
            )?;
            Ok::<_, CaptureError>((stdout, stderr))
        };
        tokio::try_join!(wait, output)
    };

    let captured = match timeout(TOOL_TIMEOUT, capture).await {
        Ok(Ok(captured)) => captured,
        Ok(Err(error)) => {
            kill_and_reap(child).await;
            return Err(capture_error(request, error));
        }
        Err(_) => {
            kill_and_reap(child).await;
            return Err(ToolError::Timeout {
                tool: request.tool,
                path: request.path.clone(),
                hint: request.hint,
            });
        }
    };
    let (status, (stdout, stderr)) = captured;
    if !status.success() {
        return Err(ToolError::NonZero {
            tool: request.tool,
            path: request.path.clone(),
            status,
            stderr: diagnostic(&stderr),
            hint: request.hint,
        });
    }
    Ok(ToolOutput { stdout })
}

async fn read_limited<R>(
    mut reader: R,
    stream: &'static str,
    limit: usize,
) -> Result<Vec<u8>, CaptureError>
where
    R: AsyncRead + Unpin,
{
    let mut output = Vec::with_capacity(limit.min(64 * 1024));
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader
            .read(&mut buffer)
            .await
            .map_err(|error| CaptureError::Read { stream, error })?;
        if read == 0 {
            return Ok(output);
        }
        if output.len().saturating_add(read) > limit {
            return Err(CaptureError::Limit { stream, limit });
        }
        output.extend_from_slice(&buffer[..read]);
    }
}

async fn kill_and_reap(child: &mut Child) {
    let _ = child.start_kill();
    let _ = timeout(TOOL_KILL_TIMEOUT, child.wait()).await;
}

fn capture_error(request: &ToolRequest, error: CaptureError) -> ToolError {
    match error {
        CaptureError::Wait(error) => ToolError::Capture {
            tool: request.tool,
            path: request.path.clone(),
            stream: "process status",
            message: error.to_string(),
            hint: request.hint,
        },
        CaptureError::Read { stream, error } => ToolError::Capture {
            tool: request.tool,
            path: request.path.clone(),
            stream,
            message: error.to_string(),
            hint: request.hint,
        },
        CaptureError::Limit { stream, limit } => ToolError::OutputLimit {
            tool: request.tool,
            path: request.path.clone(),
            stream,
            limit,
            hint: request.hint,
        },
    }
}

fn diagnostic(stderr: &[u8]) -> String {
    let truncated = stderr.len() > DIAGNOSTIC_LIMIT;
    let stderr = &stderr[..stderr.len().min(DIAGNOSTIC_LIMIT)];
    let mut message = String::from_utf8_lossy(stderr).trim().to_owned();
    if message.is_empty() {
        message = "no stderr output".to_owned();
    } else if truncated {
        message.push_str(" [truncated]");
    }
    message
}
