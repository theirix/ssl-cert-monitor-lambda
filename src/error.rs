#[derive(thiserror::Error, Debug)]
pub enum MonitorError {
    #[error("network error: {0}")]
    Network(String),
    #[error("certificate error: {0}")]
    Certificate(String),
    #[error("config error: {0}")]
    Config(String),
    //#[error("unknown error")]
    //Unknown,
}
