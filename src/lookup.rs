use crate::client::LdapClient;
use crate::error::LdapError;
use crate::model::User;
use crate::search::{search_by_any, search_by_display_name, search_by_mail, search_by_username};

impl LdapClient {
    /// Look up a user by their sAMAccountName (Windows login name)
    pub async fn search_by_username(&mut self, username: &str) -> Result<Option<User>, LdapError> {
        search_by_username(&mut self.ldap, &self.config, username).await
    }

    /// Look up a user by their email address (mail attribute)
    pub async fn search_by_mail(&mut self, mail: &str) -> Result<Option<User>, LdapError> {
        search_by_mail(&mut self.ldap, &self.config, mail).await
    }

    /// Look up a user by their display name — exact match
    pub async fn search_by_display_name(&mut self, name: &str) -> Result<Option<User>, LdapError> {
        search_by_display_name(&mut self.ldap, &self.config, name).await
    }

    /// Try sAMAccountName → mail → displayName in order, return first match
    pub async fn search_by_any(&mut self, query: &str) -> Result<Option<User>, LdapError> {
        search_by_any(&mut self.ldap, &self.config, query).await
    }
}
