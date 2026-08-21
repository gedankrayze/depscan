use super::osv::sync::*;
use super::*;
use std::{
    io::{Cursor, Write},
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    sync::Notify,
    task::JoinHandle,
};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_json, header, method, path},
};
use zip::write::SimpleFileOptions;

mod support;
use support::*;

mod cache;
mod http;
mod offline;
// The `*_cases` names avoid colliding with the production `osv`/`registry`/`sync` modules that
// the glob import above already binds in this scope; `#[path]` keeps the test files in the
// directories that mirror the production tree.
#[path = "osv/mod.rs"]
mod osv_cases;
#[path = "registry/mod.rs"]
mod registry_cases;
#[path = "sync/mod.rs"]
mod sync_cases;
