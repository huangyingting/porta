use thiserror::Error;

/// A gateway refused valid credentials because of an account limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountDenial {
    Expired,
    QuotaExceeded,
    /// The device is enrolled but waits for administrator approval.
    DevicePending,
    /// The account accepts no new devices.
    EnrollmentClosed,
    /// An administrator refused this device.
    DeviceDenied,
    /// The gateway requires a newer version of the app.
    ClientOutdated,
}

impl AccountDenial {
    /// Parses the gateway's `X-Porta-Reason` value.
    pub fn from_reason(reason: &str) -> Option<Self> {
        match reason {
            "account-expired" => Some(Self::Expired),
            "quota-exceeded" => Some(Self::QuotaExceeded),
            "device-pending" => Some(Self::DevicePending),
            "enrollment-closed" => Some(Self::EnrollmentClosed),
            "device-denied" => Some(Self::DeviceDenied),
            "client-outdated" => Some(Self::ClientOutdated),
            _ => None,
        }
    }

    /// Stable identifier for user interfaces that localize the message.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Expired => "account-expired",
            Self::QuotaExceeded => "quota-exceeded",
            Self::DevicePending => "device-pending",
            Self::EnrollmentClosed => "enrollment-closed",
            Self::DeviceDenied => "device-denied",
            Self::ClientOutdated => "client-outdated",
        }
    }

    pub const fn message(self) -> &'static str {
        match self {
            Self::Expired => "the gateway account has expired; ask the administrator to renew it",
            Self::QuotaExceeded => {
                "the gateway account has used its monthly data quota; access resumes next month or when the administrator raises it"
            }
            Self::DevicePending => {
                "this device is waiting for administrator approval; connect again once it is approved"
            }
            Self::EnrollmentClosed => {
                "this account accepts no new devices; ask the administrator to allow enrollment"
            }
            Self::DeviceDenied => "the administrator has not allowed this device to connect",
            Self::ClientOutdated => {
                "this version of Porta is too old for the gateway; install the latest version from the downloads page"
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
    /// The gateway answered but cannot admit this client now, for example a
    /// replica that sends new devices to its primary; another gateway may.
    #[error("retryable: {0}")]
    Refused(String),
    #[error("{0}")]
    Permanent(String),
    /// The TLS handshake with the gateway failed, as when a captive network
    /// answers in its place until the user signs in.
    #[error("TLS handshake failed: {0}; if this network has a sign-in page, sign in to it first")]
    Intercepted(String),
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
        matches!(
            self,
            Self::Permanent(_) | Self::Denied(_) | Self::Intercepted(_)
        )
    }

    /// The network may be holding the connection for sign-in. Clients whose
    /// leak protection would block the sign-in page retry these.
    pub fn is_intercepted(&self) -> bool {
        matches!(self, Self::Intercepted(_))
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
            Self::TransportUnavailable(_) | Self::Retryable(_) | Self::Refused(_) | Self::Closed
        )
    }
}
