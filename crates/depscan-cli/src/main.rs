mod app;
mod external_tools;
mod secure_fs;
mod vulnerability_resolution;

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    app::run().await
}
