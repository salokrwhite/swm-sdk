use thiserror::Error;

/// SDK error category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    Configuration,
    UnsupportedPlatform,
    Network,
    Timeout,
    Protocol,
    Identity,
    Cryptographic,
    Clock,
    Session,
    Unauthorized,
    Validation,
    RateLimit,
    Api,
    DeviceBlocked,
    UnsupportedVersion,
    UpdateRegionBlocked,
    FeedbackDisabled,
    Integrity,
    OperationAuthorization,
    OfflineBudget,
}

/// Common SDK error.
#[derive(Debug, Error)]
#[error("{message}")]
pub struct Error {
    pub kind: ErrorKind,
    pub status_code: Option<u16>,
    pub code: Option<String>,
    pub message: String,
    pub response_body: Option<String>,
    pub retry_after: Option<std::time::Duration>,
    pub minimum_supported_version: Option<String>,
    pub source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl Error {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            status_code: None,
            code: None,
            message: message.into(),
            response_body: None,
            retry_after: None,
            minimum_supported_version: None,
            source: None,
        }
    }

    pub fn with_code(mut self, code: impl Into<String>) -> Self {
        self.code = Some(code.into());
        self
    }

    pub fn with_status(mut self, status: u16) -> Self {
        self.status_code = Some(status);
        self
    }

    pub fn with_response(mut self, body: impl Into<String>) -> Self {
        self.response_body = Some(body.into());
        self
    }

    pub fn with_source(mut self, source: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    pub fn is_kind(&self, kind: ErrorKind) -> bool {
        self.kind == kind
    }
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Error::new(ErrorKind::Protocol, value.to_string()).with_source(value)
    }
}

impl From<url::ParseError> for Error {
    fn from(value: url::ParseError) -> Self {
        Error::new(ErrorKind::Configuration, value.to_string()).with_source(value)
    }
}

impl From<reqwest::Error> for Error {
    fn from(value: reqwest::Error) -> Self {
        let kind = if value.is_timeout() {
            ErrorKind::Timeout
        } else {
            ErrorKind::Network
        };
        Error::new(kind, value.to_string()).with_source(value)
    }
}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Error::new(ErrorKind::Validation, value.to_string()).with_source(value)
    }
}
