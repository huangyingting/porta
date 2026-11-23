use thiserror::Error;

/// A gateway refused valid credentials because of an account limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountDenial {
    Expired,
    QuotaExceeded,
}

impl AccountDenial {
    /// Parses the gateway's `X-Porta-Reason` value.
    pub fn from_reason(reason: &str) -> Option<Self> {
        match reason {
            "account-expired" => Some(Self::Expired),
            "quota-exceeded" => Some(Self::QuotaExceeded),
            _ => None,
        }
    }

    /// Stable identifier for user interfaces that localize the message.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Expired => "account-expired",
            Self::QuotaExceeded => "quota-exceeded",
        }
    }

    pub const fn message(self) -> &'static str {
        match self {
            Self::Expired => "the gateway account has expired; ask the administrator to renew it",
            Self::QuotaExceeded => {
                "the gateway account has used its monthly data quota; access resumes next month or when the administrator raises it"
            }
        }
    }
}

#[derive(Clone, Debug, Error)]
pub enum ClientError {
    #[error("transport unavailable: {0}")]
    TransportUnavailable(String),
    #[error("retryable: {0}")]
    Retryable(String),
    #[error("{0}")]
    Permanent(String),
    /// Permanent refusal of a valid account; see [`AccountDenial`].
    #[error("{}", .0.message())]
    Denied(AccountDenial),
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

    /// Failures that retrying cannot fix without operator action.
    pub fn is_permanent(&self) -> bool {
        matches!(self, Self::Permanent(_) | Self::Denied(_))
    }

    pub fn denial(&self) -> Option<AccountDenial> {
        match self {
            Self::Denied(denial) => Some(*denial),
            _ => None,
        }
    }

    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::TransportUnavailable(_) | Self::Retryable(_) | Self::Closed
        )
    }
}
