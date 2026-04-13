use tracing::{debug, warn};

use crate::client::LdapClient;
use crate::error::LdapError;
use crate::model::{AuthResult, User};
use crate::search::search_by_username;

impl LdapClient {
    /// Auth user against AD
    /// Takes both usrname and full UPN, usrname is added to config.defualt_domain
    /// returns AuthResult::Authenticated(User), AuthResult::InvalidCredentials or AuthResults::UserNotFound
    /// Network err return Err(LdapError)
    pub async fn authenticate(
        &mut self,
        username: &str,
        password: &str,
    ) -> Result<AuthResult, LdapError> {
        let upn = self.config.to_upn(username);

        debug!("Attempting to bind for {}", upn);

        //bind sends UPN + pword to AD over TLS
        let result = self.ldap.simple_bind(&upn, password).await?;

        // AD results codes rc 0 success, rc 49 invalid credentials
        match result.rc {
            0 => {
                debug!("bind successful for {}", upn);
                let user = match search_by_username(&mut self.ldap, &self.config, username).await {
                    Ok(Some(user)) => user,
                    Ok(None) => {
                        warn!("search found nothing for {}", upn);
                        User { 
                            username: username.to_string(),
                            upn: upn.clone(),
                            display_name: username.to_string(),
                            email: upn.clone(),
                            groups: Vec::new(),
                        }
                    }
                    Err(e) => {
                        warn!("search error for {}: {:?}", upn, e);
                        User { 
                            username: username.to_string(),
                            upn: upn.clone(),
                            display_name: username.to_string(),
                            email: upn.clone(),
                            groups: Vec::new(),
                        }
                    }
                };
                Ok(AuthResult::Authenticated(user))
            }
            49 => {
                debug!("invalid credentials for {}", upn);
                Ok(AuthResult::InvalidCredentials)
            }
            _ => {
                // any other result code
                Err(LdapError::Connection(format!(
                    "unexpected LDAP result code for {} for {}",
                    result.rc, upn
                )))
            }
        }
    }
}
