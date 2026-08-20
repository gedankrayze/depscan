use super::*;

pub(super) fn resolve_executable(
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
