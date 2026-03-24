use thiserror::Error;

#[derive(Debug, Error)]
pub enum LdapError {
    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("user not found: {0}")]
    UserNotFound(String),

    #[error("connection error: {0}")]
    Connection(String),

    #[error("search error: {0}")]
    Search(String),

    #[error("ldap protocol error: {0}")]
    Protocol(#[from] ldap3::LdapError),
}
