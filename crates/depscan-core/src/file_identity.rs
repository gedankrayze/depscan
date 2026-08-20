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
#[path = "file_identity/tests.rs"]
mod tests;
