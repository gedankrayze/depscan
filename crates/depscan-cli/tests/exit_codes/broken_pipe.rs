use super::support::*;
use std::process::Stdio;

// Rust ignores SIGPIPE, so writing a report into a pipe whose consumer already exited (for
// example `depscan | head`) must surface as a suppressed BrokenPipe error and the command's
// ordinary exit code, never as a write panic. Closing the read end before the child starts
// makes the very first stdout write fail deterministically.
fn run_with_closed_stdout(mut command: Command, arguments: &[&str]) -> Output {
    let (read_end, write_end) = std::io::pipe().expect("create stdout pipe");
    drop(read_end);
    let child = command
        .args(arguments)
        .stdout(write_end)
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn depscan with a closed stdout consumer");
    child.wait_with_output().expect("wait for depscan")
}

fn assert_no_panic_on_stderr(output: &Output) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("panicked"),
        "closed stdout must not panic the CLI: {stderr}"
    );
}

#[test]
fn offline_scan_with_closed_stdout_keeps_the_scan_exit_code() {
    let project = TestProject::rust("broken-pipe-scan");
    project.seed_clean("1.0.0");
    project.seed_empty_offline_dump();

    let output = run_with_closed_stdout(
        command(&project.cache),
        &[
            "scan",
            "--offline",
            "--format",
            "json",
            project.directory.path().to_str().expect("UTF-8 path"),
        ],
    );

    assert_no_panic_on_stderr(&output);
    assert_exit(&output, 0);
}

#[test]
fn completions_with_closed_stdout_exit_cleanly() {
    let project = TestProject::rust("broken-pipe-completions");

    let output = run_with_closed_stdout(command(&project.cache), &["completions", "bash"]);

    assert_no_panic_on_stderr(&output);
    assert_exit(&output, 0);
}

#[test]
fn cache_path_with_closed_stdout_exits_cleanly() {
    let project = TestProject::rust("broken-pipe-cache-path");

    let output = run_with_closed_stdout(command(&project.cache), &["cache", "path"]);

    assert_no_panic_on_stderr(&output);
    assert_exit(&output, 0);
}
