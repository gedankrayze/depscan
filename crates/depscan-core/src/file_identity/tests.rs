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
