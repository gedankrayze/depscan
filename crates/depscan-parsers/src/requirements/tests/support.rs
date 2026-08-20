use super::*;

#[cfg(unix)]
use std::os::unix::fs::symlink as symlink_path;
#[cfg(windows)]
use std::os::windows::fs::{symlink_dir, symlink_file};

pub(super) fn write(path: &Path, text: impl AsRef<[u8]>) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(path, text).unwrap();
}

#[cfg(unix)]
pub(super) fn symlink_file(original: &Path, link: &Path) -> std::io::Result<()> {
    symlink_path(original, link)
}

#[cfg(unix)]
pub(super) fn symlink_directory(original: &Path, link: &Path) -> std::io::Result<()> {
    symlink_path(original, link)
}

#[cfg(windows)]
pub(super) fn symlink_directory(original: &Path, link: &Path) -> std::io::Result<()> {
    symlink_dir(original, link)
}

#[cfg(any(unix, windows))]
#[derive(Clone, Copy)]
pub(super) enum ReplacementKind {
    Regular,
    SymbolicLink,
}

#[cfg(any(unix, windows))]
pub(super) enum SwapOutcome {
    Swapped,
    Denied,
    Inconclusive(String),
}

#[cfg(any(unix, windows))]
pub(super) fn attempt_namespace_swap(
    original: &Path,
    moved: &Path,
    replacement: &Path,
    kind: ReplacementKind,
    directory: bool,
) -> SwapOutcome {
    if fs::rename(original, moved).is_err() {
        return SwapOutcome::Denied;
    }
    let installed = match kind {
        ReplacementKind::Regular => fs::rename(replacement, original),
        ReplacementKind::SymbolicLink if directory => symlink_directory(replacement, original),
        ReplacementKind::SymbolicLink => symlink_file(replacement, original),
    };
    if installed.is_ok() {
        return SwapOutcome::Swapped;
    }
    match fs::rename(moved, original) {
        Ok(()) => SwapOutcome::Denied,
        Err(error) => SwapOutcome::Inconclusive(format!(
            "replacement install failed and original namespace could not be restored: {error}"
        )),
    }
}

#[cfg(any(unix, windows))]
pub(super) fn parse_with_boundary_swap<F>(
    root: &Path,
    boundary: ReadBoundary,
    target: &Path,
    swap: F,
) -> (Result<Vec<Package>, ParseError>, SwapOutcome)
where
    F: FnOnce() -> SwapOutcome + Send + 'static,
{
    let barrier = Arc::new(Barrier::new(2));
    let worker_barrier = barrier.clone();
    let worker = thread::spawn(move || {
        worker_barrier.wait();
        let outcome = swap();
        worker_barrier.wait();
        outcome
    });
    let mut reached = false;
    let mut hook = |actual, relative: &Path, _display: &Path| {
        if !reached && actual == boundary && relative == target {
            reached = true;
            barrier.wait();
            barrier.wait();
        }
        Ok(())
    };
    let result = parse_with_limits_and_hook(root, RequirementsLimits::default(), &mut hook);
    assert!(
        reached,
        "requirements parser did not reach {boundary:?} for {target:?}"
    );
    (
        result,
        worker.join().expect("join requirements swap worker"),
    )
}

#[cfg(any(unix, windows))]
pub(super) fn assert_swap_result(
    result: Result<Vec<Package>, ParseError>,
    outcome: SwapOutcome,
    safe_package: &str,
    sentinel: &str,
) {
    match outcome {
        SwapOutcome::Swapped => {
            let error = result.expect_err("a successful namespace swap must fail closed");
            let message = error.to_string();
            assert!(message.contains("changed"), "{message}");
            assert!(!message.contains(sentinel), "{message}");
        }
        SwapOutcome::Denied => {
            let packages = result.expect("an OS-denied swap must preserve the original parse");
            let package_names = names(&packages);
            assert!(package_names.contains(&safe_package), "{package_names:?}");
            assert!(!package_names.contains(&sentinel), "{package_names:?}");
        }
        SwapOutcome::Inconclusive(message) => panic!("{message}"),
    }
}

pub(super) fn names(packages: &[Package]) -> Vec<&str> {
    packages
        .iter()
        .map(|package| package.name.as_str())
        .collect()
}
