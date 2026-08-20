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

mod capture;
mod executable;

use capture::run;
use executable::resolve_executable;

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
