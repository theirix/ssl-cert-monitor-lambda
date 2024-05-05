#[derive(thiserror::Error, Debug)]
pub enum MonitorError {
    #[error("network error: {0}")]
    Network(std::io::Error),
    #[error("TLS error: {0}")]
    Tls(rustls::Error),
    #[error("certificate error: {0}")]
    Certificate(String),
    #[error("config error: {0}")]
    Config(String),
    #[error("certificate expired")]
    Expired,
    #[error("general error: {0}")]
    General(String),
}
