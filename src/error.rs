//! dhcpd error type.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DhcpdError {
    #[error("config: {0}")]
    Config(String),

    #[error("vpp: {0}")]
    Vpp(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("control: {0}")]
    Control(String),

    #[error("parse: {0}")]
    Parse(String),

    #[error("lease: {0}")]
    Lease(String),

    #[error("allocator: {0}")]
    Allocator(String),
}
