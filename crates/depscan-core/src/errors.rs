use crate::Ecosystem;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ParseError {
    #[error("failed to parse {path}: {message}")]
    Invalid { path: PathBuf, message: String },
    #[error("I/O for {path}: {message}")]
    Io { path: PathBuf, message: String },
}

#[derive(Debug, Clone, Error)]
#[non_exhaustive]
pub enum ProviderError {
    #[error("network provider failed: {0}")]
    Network(String),
    #[error("offline data is unavailable: {0}")]
    Offline(String),
    #[error("invalid package name {name:?} for {ecosystem:?}: {reason}")]
    InvalidPackageName {
        ecosystem: Ecosystem,
        name: String,
        reason: String,
    },
    #[error("invalid provider response: {0}")]
    InvalidResponse(String),
    #[error("cache error: {0}")]
    Cache(String),
}
