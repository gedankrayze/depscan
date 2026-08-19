use super::ReadBoundary;
use depscan_core::ParseError;
use std::path::Path;

#[cfg(debug_assertions)]
const PROCESS_BARRIER_ENV: &str = "DEPSCAN_INTERNAL_TEST_REQUIREMENTS_BARRIER_83E3A8B5D3B4497A";
#[cfg(debug_assertions)]
const PROCESS_BARRIER_NONCE: &str = "ds060-5c9847fe18b243c6a417e737d9570bf1";

#[cfg(debug_assertions)]
pub(super) fn process_test_barrier(
    boundary: ReadBoundary,
    relative: &Path,
    display: &Path,
) -> Result<(), ParseError> {
    use super::invalid;
    use std::{
        fs,
        time::{Duration, Instant},
    };

    let Some(configuration) = std::env::var_os(PROCESS_BARRIER_ENV) else {
        return Ok(());
    };
    let configuration = configuration.to_string_lossy();
    let mut fields = configuration.splitn(4, '\t');
    let Some(nonce) = fields.next() else {
        return Ok(());
    };
    let Some(stage) = fields.next() else {
        return Ok(());
    };
    let Some(target) = fields.next() else {
        return Ok(());
    };
    let Some(directory) = fields.next() else {
        return Ok(());
    };
    if nonce != PROCESS_BARRIER_NONCE
        || stage != boundary.label()
        || target != relative.to_string_lossy()
    {
        return Ok(());
    }

    let directory = Path::new(directory);
    let ready = directory.join(format!("{PROCESS_BARRIER_NONCE}.ready"));
    let resume = directory.join(format!("{PROCESS_BARRIER_NONCE}.continue"));
    fs::write(&ready, b"ready").map_err(|error| {
        invalid(
            display,
            format!("cannot signal requirements test barrier: {error}"),
        )
    })?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while !resume.is_file() {
        if Instant::now() >= deadline {
            return Err(invalid(display, "requirements test barrier timed out"));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Ok(())
}

#[cfg(not(debug_assertions))]
pub(super) fn process_test_barrier(
    _boundary: ReadBoundary,
    _relative: &Path,
    _display: &Path,
) -> Result<(), ParseError> {
    Ok(())
}
