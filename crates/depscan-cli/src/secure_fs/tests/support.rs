use super::*;
pub(super) use std::fs;
#[cfg(not(windows))]
pub(super) use std::{
    sync::{Arc, Barrier},
    thread,
};
pub(super) use tempfile::tempdir;

pub(super) fn prepare_output(root: &Path, configured: &Path, display: &Path) -> ConfinedOutput {
    ConfinedOutput::prepare(
        ScanRoot::open(root).expect("open scan root"),
        configured,
        display,
    )
    .expect("prepare output")
}

#[cfg(windows)]
pub(super) fn assert_windows_handle_blocks_rename(error: &io::Error) {
    assert!(
        error.raw_os_error().is_some(),
        "Windows must report an OS error while the directory capability is held: {error}"
    );
}

#[cfg(any(unix, windows))]
#[derive(Debug)]
pub(super) enum RegularFileSwap {
    Denied(io::ErrorKind),
    Swapped { original: PathBuf, moved: PathBuf },
}

#[cfg(any(unix, windows))]
pub(super) fn attempt_regular_file_swap(
    original: &Path,
    moved: &Path,
    replacement: &Path,
) -> RegularFileSwap {
    match fs::rename(original, moved) {
        Ok(()) => match fs::rename(replacement, original) {
            Ok(()) => RegularFileSwap::Swapped {
                original: original.to_path_buf(),
                moved: moved.to_path_buf(),
            },
            Err(error) => {
                fs::rename(moved, original).expect("restore original after replacement denial");
                RegularFileSwap::Denied(error.kind())
            }
        },
        Err(error) => RegularFileSwap::Denied(error.kind()),
    }
}

#[cfg(any(unix, windows))]
pub(super) fn restore_regular_file_swap(outcome: RegularFileSwap) -> bool {
    match outcome {
        RegularFileSwap::Swapped { original, moved } => {
            fs::remove_file(&original).expect("remove installed replacement");
            fs::rename(moved, original).expect("restore original file");
            true
        }
        #[cfg(unix)]
        RegularFileSwap::Denied(kind) => {
            panic!("regular-file replacement unexpectedly failed on Unix: {kind:?}")
        }
        #[cfg(windows)]
        RegularFileSwap::Denied(kind) => {
            assert!(
                matches!(
                    kind,
                    io::ErrorKind::PermissionDenied
                        | io::ErrorKind::Unsupported
                        | io::ErrorKind::Other
                ),
                "unexpected Windows regular-file replacement error: {kind:?}"
            );
            false
        }
    }
}

#[cfg(unix)]
pub(super) fn create_directory_symlink(target: &Path, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
pub(super) fn create_directory_symlink(target: &Path, link: &Path) -> io::Result<()> {
    std::os::windows::fs::symlink_dir(target, link)
}

#[cfg(unix)]
pub(super) fn create_file_symlink(target: &Path, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
pub(super) fn create_file_symlink(target: &Path, link: &Path) -> io::Result<()> {
    std::os::windows::fs::symlink_file(target, link)
}
