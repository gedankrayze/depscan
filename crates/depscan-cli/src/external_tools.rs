use depscan_core::Package;
use depscan_parsers::{parse_bun_lockb_output, parse_dotnet_list_json};
use std::{
    env,
    ffi::OsString,
    fs, io,
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    time::Duration,
};
use tempfile::TempDir;
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::{Child, Command},
    time::timeout,
};

const TOOL_TIMEOUT: Duration = Duration::from_secs(10);
const TOOL_KILL_TIMEOUT: Duration = Duration::from_secs(1);
const STDOUT_LIMIT: usize = 8 * 1024 * 1024;
const STDERR_LIMIT: usize = 1024 * 1024;
const DIAGNOSTIC_LIMIT: usize = 4 * 1024;

#[derive(Debug, Error)]
pub enum ToolError {
    #[error(
        "{tool} executable was not found on the absolute entries in PATH while reading {path}; {hint}"
    )]
    Missing {
        tool: &'static str,
        path: PathBuf,
        hint: &'static str,
    },
    #[error("cannot prepare the isolated {tool} environment for {path}: {message}")]
    Setup {
        tool: &'static str,
        path: PathBuf,
        message: String,
    },
    #[error("failed to start {tool} while reading {path}: {message}; {hint}")]
    Spawn {
        tool: &'static str,
        path: PathBuf,
        message: String,
        hint: &'static str,
    },
    #[error("{tool} timed out after 10 seconds while reading {path}; {hint}")]
    Timeout {
        tool: &'static str,
        path: PathBuf,
        hint: &'static str,
    },
    #[error("{tool} {stream} exceeded the {limit}-byte output limit while reading {path}; {hint}")]
    OutputLimit {
        tool: &'static str,
        path: PathBuf,
        stream: &'static str,
        limit: usize,
        hint: &'static str,
    },
    #[error("failed to capture {tool} {stream} while reading {path}: {message}; {hint}")]
    Capture {
        tool: &'static str,
        path: PathBuf,
        stream: &'static str,
        message: String,
        hint: &'static str,
    },
    #[error("{tool} exited with {status} while reading {path}: {stderr}; {hint}")]
    NonZero {
        tool: &'static str,
        path: PathBuf,
        status: ExitStatus,
        stderr: String,
        hint: &'static str,
    },
    #[error("{tool} emitted non-UTF-8 stdout while reading {path}: {message}; {hint}")]
    Utf8 {
        tool: &'static str,
        path: PathBuf,
        message: String,
        hint: &'static str,
    },
    #[error("{tool} emitted malformed dependency data for {path}: {message}; {hint}")]
    Malformed {
        tool: &'static str,
        path: PathBuf,
        message: String,
        hint: &'static str,
    },
}

impl ToolError {
    /// A Bun manifest fallback is safe only when the package-manager process never started.
    pub fn is_pre_execution_failure(&self) -> bool {
        matches!(
            self,
            Self::Missing { .. } | Self::Setup { .. } | Self::Spawn { .. }
        )
    }
}

struct ToolRequest {
    tool: &'static str,
    arguments: Vec<OsString>,
    path: PathBuf,
    working_directory: PathBuf,
    hint: &'static str,
}

struct ToolOutput {
    stdout: Vec<u8>,
}

#[derive(Debug)]
enum CaptureError {
    Wait(io::Error),
    Read {
        stream: &'static str,
        error: io::Error,
    },
    Limit {
        stream: &'static str,
        limit: usize,
    },
}

pub async fn parse_bun_binary_lock(path: &Path) -> Result<Vec<Package>, ToolError> {
    let working_directory = controlled_working_directory("bun", path)?;
    let output = run(ToolRequest {
        tool: "bun",
        arguments: vec![OsString::from("bun.lockb")],
        path: path.to_path_buf(),
        working_directory,
        hint: "install Bun or commit the generated bun.lock text lockfile",
    })
    .await?;
    let stdout = decode_stdout("bun", path, output.stdout)?;
    parse_bun_lockb_output(path, &stdout).map_err(|error| ToolError::Malformed {
        tool: "bun",
        path: path.to_path_buf(),
        message: error.to_string(),
        hint: "regenerate bun.lockb with a supported Bun release or commit bun.lock",
    })
}

pub async fn parse_dotnet_project(path: &Path, offline: bool) -> Result<Vec<Package>, ToolError> {
    let working_directory = controlled_working_directory("dotnet", path)?;
    let project_name = path.file_name().ok_or_else(|| ToolError::Setup {
        tool: "dotnet",
        path: path.to_path_buf(),
        message: "project path has no file name".to_owned(),
    })?;
    let project_argument = Path::new(".").join(project_name).into_os_string();
    let mut arguments = vec![
        OsString::from("list"),
        project_argument,
        OsString::from("package"),
        OsString::from("--include-transitive"),
        OsString::from("--format"),
        OsString::from("json"),
        OsString::from("--output-version"),
        OsString::from("1"),
        OsString::from("--verbosity"),
        OsString::from("quiet"),
    ];
    if offline {
        arguments.push(OsString::from("--no-restore"));
    }
    let output = run(ToolRequest {
        tool: "dotnet",
        arguments,
        path: path.to_path_buf(),
        working_directory,
        hint: "install a .NET SDK 7.0.200 or newer and restore the project, or commit packages.lock.json",
    })
    .await?;
    let stdout = decode_stdout("dotnet", path, output.stdout)?;
    parse_dotnet_list_json(path, &stdout).map_err(|error| ToolError::Malformed {
        tool: "dotnet",
        path: path.to_path_buf(),
        message: error.to_string(),
        hint: "use a .NET SDK that supports JSON output version 1, or commit packages.lock.json",
    })
}

fn controlled_working_directory(tool: &'static str, path: &Path) -> Result<PathBuf, ToolError> {
    let parent = path.parent().unwrap_or(Path::new("."));
    fs::canonicalize(parent).map_err(|error| ToolError::Setup {
        tool,
        path: path.to_path_buf(),
        message: format!(
            "cannot resolve working directory {}: {error}",
            parent.display()
        ),
    })
}

fn decode_stdout(tool: &'static str, path: &Path, stdout: Vec<u8>) -> Result<String, ToolError> {
    String::from_utf8(stdout).map_err(|error| ToolError::Utf8 {
        tool,
        path: path.to_path_buf(),
        message: error.utf8_error().to_string(),
        hint: "ensure the package manager is configured to emit UTF-8 machine-readable output",
    })
}

async fn run(request: ToolRequest) -> Result<ToolOutput, ToolError> {
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

fn resolve_executable(
    tool: &'static str,
    request: &ToolRequest,
) -> Result<(PathBuf, OsString), ToolError> {
    let path = env::var_os("PATH").ok_or_else(|| ToolError::Missing {
        tool,
        path: request.path.clone(),
        hint: request.hint,
    })?;
    let directories = env::split_paths(&path)
        .filter(|directory| directory.is_absolute())
        .collect::<Vec<_>>();
    let executable = directories
        .iter()
        .flat_map(|directory| executable_candidates(directory, tool))
        .find(|candidate| is_executable(candidate))
        .ok_or_else(|| ToolError::Missing {
            tool,
            path: request.path.clone(),
            hint: request.hint,
        })?;
    let sanitized_path = env::join_paths(&directories).map_err(|error| ToolError::Setup {
        tool,
        path: request.path.clone(),
        message: format!("cannot construct a sanitized PATH: {error}"),
    })?;
    Ok((executable, sanitized_path))
}

fn executable_candidates(directory: &Path, tool: &str) -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        vec![directory.join(format!("{tool}.exe")), directory.join(tool)]
    }
    #[cfg(not(windows))]
    {
        vec![directory.join(tool)]
    }
}

fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}
