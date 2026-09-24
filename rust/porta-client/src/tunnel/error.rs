use thiserror::Error;

#[derive(Clone, Debug, Error)]
pub enum ClientError {
    #[error("transport unavailable: {0}")]
    TransportUnavailable(String),
    #[error("retryable: {0}")]
    Retryable(String),
    #[error("{0}")]
    Permanent(String),
    #[error("tunnel is closed")]
    Closed,
}

impl ClientError {
    pub fn unavailable(error: impl std::fmt::Display) -> Self {
        Self::TransportUnavailable(error.to_string())
    }

    pub fn retryable(error: impl std::fmt::Display) -> Self {
        Self::Retryable(error.to_string())
    }

    pub fn permanent(error: impl std::fmt::Display) -> Self {
        Self::Permanent(error.to_string())
    }

    pub fn is_transport_unavailable(&self) -> bool {
        matches!(self, Self::TransportUnavailable(_))
    }

    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::TransportUnavailable(_) | Self::Retryable(_) | Self::Closed
        )
    }
}
