pub mod config;
pub mod error;
pub mod model;

mod auth;
mod client;
mod lookup;
mod search;

//export type callers
pub use client::LdapClient;
pub use error::LdapError;
pub use model::{AuthResult, Group, User};
