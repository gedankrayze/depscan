//! Held-handle filesystem identity for security-sensitive revalidation.

use std::{fs::File, io};

/// Workspace-internal stable filesystem identity paired with an owned handle that keeps the
/// object alive.
///
/// Compare identities while both values are in scope. Retaining both handles prevents a removed
/// object's platform identifier from being reused between the expected and candidate lookups.
#[derive(Debug)]
pub struct FileIdentity {
    key: IdentityKey,
    _handle: File,
}

impl FileIdentity {
    /// Clones `file`, identifies the cloned handle, and retains it for this value's lifetime.
    pub fn from_file(file: &File) -> io::Result<Self> {
        Self::from_owned_file(file.try_clone()?)
    }

    /// Identifies and retains an owned file or directory handle.
    pub fn from_owned_file(file: File) -> io::Result<Self> {
        let key = platform_file_identity(&file)?;
        Ok(Self { key, _handle: file })
    }
}

impl PartialEq for FileIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl Eq for FileIdentity {}

#[derive(Debug, PartialEq, Eq)]
enum IdentityKey {
    #[cfg(unix)]
    Unix { device: u64, inode: u64 },
    #[cfg(windows)]
    Windows {
        volume_serial_number: u64,
        file_id: [u8; 16],
    },
}

#[cfg(unix)]
fn platform_file_identity(file: &File) -> io::Result<IdentityKey> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata()?;
    Ok(IdentityKey::Unix {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn platform_file_identity(file: &File) -> io::Result<IdentityKey> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx},
    };

    let mut information = FILE_ID_INFO::default();
    // SAFETY: `file` owns a valid handle for this call, `information` provides a correctly sized
    // initialized writable FILE_ID_INFO buffer, and the return value is checked before its fields
    // are trusted.
    let succeeded = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as HANDLE,
            FileIdInfo,
            (&raw mut information).cast(),
            u32::try_from(std::mem::size_of::<FILE_ID_INFO>())
                .expect("FILE_ID_INFO size fits a Windows DWORD"),
        )
    };
    if succeeded == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(IdentityKey::Windows {
        volume_serial_number: information.VolumeSerialNumber,
        file_id: information.FileId.Identifier,
    })
}

#[cfg(not(any(unix, windows)))]
fn platform_file_identity(_file: &File) -> io::Result<IdentityKey> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "held-handle file identity is unsupported on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[cfg(any(unix, windows))]
    #[test]
    fn retained_handle_identity_distinguishes_replacement_files() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let original_path = directory.path().join("original");
        let replacement_path = directory.path().join("replacement");
        fs::write(&original_path, b"original").expect("write original");
        fs::write(&replacement_path, b"replacement").expect("write replacement");
        let original = File::open(&original_path).expect("open original");
        let replacement = File::open(&replacement_path).expect("open replacement");
        let expected = FileIdentity::from_file(&original).expect("identify original");
        let candidate = FileIdentity::from_owned_file(replacement).expect("identify replacement");

        assert_ne!(expected, candidate);
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn retained_handle_identity_matches_a_hard_link_alias() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let original_path = directory.path().join("original");
        let alias_path = directory.path().join("alias");
        fs::write(&original_path, b"original").expect("write original");
        fs::hard_link(&original_path, &alias_path).expect("create hard link");
        let original = File::open(&original_path).expect("open original");
        let alias = File::open(&alias_path).expect("open alias");
        let expected = FileIdentity::from_file(&original).expect("identify original");
        let candidate = FileIdentity::from_file(&alias).expect("identify alias");

        assert_eq!(expected, candidate);
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn borrowed_and_owned_constructors_identify_the_same_handle() {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let path = directory.path().join("file");
        fs::write(&path, b"contents").expect("write file");
        let borrowed_file = File::open(&path).expect("open borrowed file");
        let owned_file = borrowed_file.try_clone().expect("clone owned file");
        let borrowed = FileIdentity::from_file(&borrowed_file).expect("identify borrowed file");
        let owned = FileIdentity::from_owned_file(owned_file).expect("identify owned file");

        assert_eq!(borrowed, owned);
    }

    #[cfg(not(any(unix, windows)))]
    #[test]
    fn unsupported_platform_fails_closed() {
        let file = tempfile::tempfile().expect("create temporary file");
        let error = FileIdentity::from_file(&file).expect_err("identity must be unsupported");

        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }

    #[cfg(windows)]
    #[test]
    fn windows_identity_compares_all_file_id_bytes() {
        let left = IdentityKey::Windows {
            volume_serial_number: 7,
            file_id: [0; 16],
        };
        let mut right_id = [0; 16];
        right_id[15] = 1;
        let right = IdentityKey::Windows {
            volume_serial_number: 7,
            file_id: right_id,
        };

        assert_ne!(left, right);
    }
}
