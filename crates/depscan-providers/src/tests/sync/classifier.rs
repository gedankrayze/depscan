use super::*;

#[cfg(any(unix, windows))]
#[test]
fn windows_namespace_swap_denials_are_stage_and_code_specific() {
    for (stage, raw_os_error) in [
        (NamespaceSwapStage::RenameOriginal, 5),
        (NamespaceSwapStage::RenameOriginal, 32),
        (NamespaceSwapStage::CreateSymlink, 5),
        (NamespaceSwapStage::CreateSymlink, 1314),
    ] {
        assert!(expected_windows_namespace_swap_denial(
            stage,
            Some(raw_os_error)
        ));
    }

    for (stage, raw_os_error) in [
        (NamespaceSwapStage::RenameOriginal, 3),
        (NamespaceSwapStage::RenameOriginal, 33),
        (NamespaceSwapStage::RenameOriginal, 12345),
        (NamespaceSwapStage::CreateSymlink, 32),
        (NamespaceSwapStage::InstallReplacement, 5),
        (NamespaceSwapStage::InstallReplacement, 32),
        (NamespaceSwapStage::InstallReplacement, 1314),
    ] {
        assert!(!expected_windows_namespace_swap_denial(
            stage,
            Some(raw_os_error)
        ));
    }
    assert!(!expected_windows_namespace_swap_denial(
        NamespaceSwapStage::RenameOriginal,
        None
    ));
}
