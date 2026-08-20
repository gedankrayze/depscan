use super::*;

#[cfg(any(unix, windows))]
#[derive(Debug)]
pub(crate) enum NamespaceSwap {
    NotAttempted,
    Denied(NamespaceSwapDenial),
    Swapped { original: PathBuf, moved: PathBuf },
}

#[cfg(any(unix, windows))]
#[derive(Debug)]
pub(crate) enum FileNamespaceSwap {
    Denied(NamespaceSwapDenial),
    Swapped { original: PathBuf, moved: PathBuf },
}

#[cfg(any(unix, windows))]
#[derive(Debug)]
pub(crate) enum RegularNamespaceSwap {
    Denied(NamespaceSwapDenial),
    Swapped {
        original: PathBuf,
        moved: PathBuf,
        replacement: PathBuf,
    },
}

#[cfg(any(unix, windows))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NamespaceSwapStage {
    RenameOriginal,
    CreateSymlink,
    InstallReplacement,
}

#[cfg(any(unix, windows))]
#[derive(Debug)]
pub(crate) struct NamespaceSwapDenial {
    stage: NamespaceSwapStage,
    error: std::io::Error,
}

#[cfg(any(unix, windows))]
pub(crate) fn expected_windows_namespace_swap_denial(
    stage: NamespaceSwapStage,
    raw_os_error: Option<i32>,
) -> bool {
    // Win32 errors returned by MoveFileExW/CreateSymbolicLinkW at the exact stages above.
    // Keep this phase-specific: an unexpected path/setup error must not masquerade as a
    // successful capability-lock test.
    const ERROR_ACCESS_DENIED: i32 = 5;
    const ERROR_SHARING_VIOLATION: i32 = 32;
    const ERROR_PRIVILEGE_NOT_HELD: i32 = 1314;

    matches!(
        (stage, raw_os_error),
        (
            NamespaceSwapStage::RenameOriginal,
            Some(ERROR_ACCESS_DENIED) | Some(ERROR_SHARING_VIOLATION)
        ) | (
            NamespaceSwapStage::CreateSymlink,
            Some(ERROR_ACCESS_DENIED) | Some(ERROR_PRIVILEGE_NOT_HELD)
        )
    )
}

#[cfg(windows)]
pub(crate) fn restore_expected_windows_denial(
    denial: NamespaceSwapDenial,
    operation: &str,
) -> bool {
    assert!(
        expected_windows_namespace_swap_denial(denial.stage, denial.error.raw_os_error()),
        "unexpected Windows {operation} denial at {:?}: kind={:?}, raw_os_error={:?}, error={}",
        denial.stage,
        denial.error.kind(),
        denial.error.raw_os_error(),
        denial.error
    );
    false
}

#[cfg(any(unix, windows))]
#[derive(Debug)]
pub(crate) enum OfflineReadSwap {
    Directory(NamespaceSwap),
    File(FileNamespaceSwap),
    Regular(RegularNamespaceSwap),
}

#[cfg(any(unix, windows))]
#[derive(Debug, Clone, Copy)]
pub(crate) enum OfflineReadSwapKind {
    Symlink,
    Regular,
}

#[cfg(any(unix, windows))]
#[derive(Debug, Clone, Copy)]
pub(crate) enum OfflineReadSwapTarget {
    Root,
    OfflineDirectory,
    Archive,
    Marker,
}

#[cfg(any(unix, windows))]
pub(crate) fn create_directory_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_dir(target, link)
    }
}

#[cfg(any(unix, windows))]
pub(crate) fn remove_directory_symlink(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        fs::remove_file(path)
    }
    #[cfg(windows)]
    {
        fs::remove_dir(path)
    }
}

#[cfg(any(unix, windows))]
pub(crate) fn create_file_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link)
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_file(target, link)
    }
}

#[cfg(any(unix, windows))]
pub(crate) fn attempt_namespace_swap(
    original: &Path,
    moved: &Path,
    external: &Path,
) -> NamespaceSwap {
    match fs::rename(original, moved) {
        Ok(()) => match create_directory_symlink(external, original) {
            Ok(()) => NamespaceSwap::Swapped {
                original: original.to_path_buf(),
                moved: moved.to_path_buf(),
            },
            Err(error) => {
                fs::rename(moved, original).expect("restore namespace after symlink denial");
                NamespaceSwap::Denied(NamespaceSwapDenial {
                    stage: NamespaceSwapStage::CreateSymlink,
                    error,
                })
            }
        },
        Err(error) => NamespaceSwap::Denied(NamespaceSwapDenial {
            stage: NamespaceSwapStage::RenameOriginal,
            error,
        }),
    }
}

#[cfg(any(unix, windows))]
pub(crate) fn restore_namespace_swap(outcome: NamespaceSwap) -> bool {
    match outcome {
        NamespaceSwap::Swapped { original, moved } => {
            remove_directory_symlink(&original).expect("remove replacement directory link");
            fs::rename(moved, original).expect("restore original namespace");
            true
        }
        #[cfg(unix)]
        NamespaceSwap::Denied(denial) => {
            panic!(
                "directory swap unexpectedly failed on Unix at {:?}: kind={:?}, raw_os_error={:?}, error={}",
                denial.stage,
                denial.error.kind(),
                denial.error.raw_os_error(),
                denial.error
            )
        }
        #[cfg(windows)]
        NamespaceSwap::Denied(denial) => restore_expected_windows_denial(denial, "directory-swap"),
        NamespaceSwap::NotAttempted => panic!("the requested sync boundary was not reached"),
    }
}

#[cfg(any(unix, windows))]
pub(crate) fn attempt_file_namespace_swap(
    original: &Path,
    moved: &Path,
    external: &Path,
) -> FileNamespaceSwap {
    match fs::rename(original, moved) {
        Ok(()) => match create_file_symlink(external, original) {
            Ok(()) => FileNamespaceSwap::Swapped {
                original: original.to_path_buf(),
                moved: moved.to_path_buf(),
            },
            Err(error) => {
                fs::rename(moved, original).expect("restore file after symlink denial");
                FileNamespaceSwap::Denied(NamespaceSwapDenial {
                    stage: NamespaceSwapStage::CreateSymlink,
                    error,
                })
            }
        },
        Err(error) => FileNamespaceSwap::Denied(NamespaceSwapDenial {
            stage: NamespaceSwapStage::RenameOriginal,
            error,
        }),
    }
}

#[cfg(any(unix, windows))]
pub(crate) fn attempt_regular_file_swap(
    original: &Path,
    moved: &Path,
    replacement: &Path,
) -> FileNamespaceSwap {
    match fs::rename(original, moved) {
        Ok(()) => match fs::rename(replacement, original) {
            Ok(()) => FileNamespaceSwap::Swapped {
                original: original.to_path_buf(),
                moved: moved.to_path_buf(),
            },
            Err(error) => {
                fs::rename(moved, original).expect("restore file after replacement denial");
                FileNamespaceSwap::Denied(NamespaceSwapDenial {
                    stage: NamespaceSwapStage::InstallReplacement,
                    error,
                })
            }
        },
        Err(error) => FileNamespaceSwap::Denied(NamespaceSwapDenial {
            stage: NamespaceSwapStage::RenameOriginal,
            error,
        }),
    }
}

#[cfg(any(unix, windows))]
pub(crate) fn restore_file_namespace_swap(outcome: FileNamespaceSwap) -> bool {
    match outcome {
        FileNamespaceSwap::Swapped { original, moved } => {
            fs::remove_file(&original).expect("remove replacement file link");
            fs::rename(moved, original).expect("restore original file");
            true
        }
        #[cfg(unix)]
        FileNamespaceSwap::Denied(denial) => {
            panic!(
                "file swap unexpectedly failed on Unix at {:?}: kind={:?}, raw_os_error={:?}, error={}",
                denial.stage,
                denial.error.kind(),
                denial.error.raw_os_error(),
                denial.error
            )
        }
        #[cfg(windows)]
        FileNamespaceSwap::Denied(denial) => restore_expected_windows_denial(denial, "file-swap"),
    }
}

#[cfg(any(unix, windows))]
pub(crate) fn attempt_regular_namespace_swap(
    original: &Path,
    moved: &Path,
    replacement: &Path,
) -> RegularNamespaceSwap {
    match fs::rename(original, moved) {
        Ok(()) => match fs::rename(replacement, original) {
            Ok(()) => RegularNamespaceSwap::Swapped {
                original: original.to_path_buf(),
                moved: moved.to_path_buf(),
                replacement: replacement.to_path_buf(),
            },
            Err(error) => {
                fs::rename(moved, original).expect("restore object after replacement denial");
                RegularNamespaceSwap::Denied(NamespaceSwapDenial {
                    stage: NamespaceSwapStage::InstallReplacement,
                    error,
                })
            }
        },
        Err(error) => RegularNamespaceSwap::Denied(NamespaceSwapDenial {
            stage: NamespaceSwapStage::RenameOriginal,
            error,
        }),
    }
}

#[cfg(any(unix, windows))]
pub(crate) fn restore_regular_namespace_swap(outcome: RegularNamespaceSwap) -> bool {
    match outcome {
        RegularNamespaceSwap::Swapped {
            original,
            moved,
            replacement,
        } => {
            fs::rename(&original, replacement).expect("restore replacement object");
            fs::rename(moved, original).expect("restore original object");
            true
        }
        #[cfg(unix)]
        RegularNamespaceSwap::Denied(denial) => {
            panic!(
                "regular namespace swap unexpectedly failed on Unix at {:?}: kind={:?}, raw_os_error={:?}, error={}",
                denial.stage,
                denial.error.kind(),
                denial.error.raw_os_error(),
                denial.error
            )
        }
        #[cfg(windows)]
        RegularNamespaceSwap::Denied(denial) => {
            restore_expected_windows_denial(denial, "regular namespace-swap")
        }
    }
}
