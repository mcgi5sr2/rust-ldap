use serde::{Deserialize, Serialize};

/// Return use after auth success
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// usrname without Domain Name
    pub username: String,

    /// full UPN
    pub upn: String,

    // Display Name
    pub display_name: String,

    /// email address
    pub email: String,

    /// All AD groups user is member of
    pub groups: Vec<Group>,
}

/// Active Directory Group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    /// the CN of the group
    pub name: String,

    /// Full distinguished name
    pub dn: String,
}

/// The result of an auth attempt
#[derive(Debug)]
pub enum AuthResult {
    // Creds valid - here is user
    Authenticated(User),

    /// Password was wrong
    InvalidCredentials,

    /// Username does not exist
    UserNotFound,
}

impl User {
    /// Check if the user belongs to a group
    pub fn is_in_group(&self, group_name: &str) -> bool {
        self.groups
            .iter()
            .any(|g| g.name.eq_ignore_ascii_case(group_name))
    }
}
