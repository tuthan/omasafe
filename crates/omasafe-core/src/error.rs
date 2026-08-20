use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid environment path: {0}")]
    InvalidPath(String),
}

pub type Result<T> = std::result::Result<T, Error>;
