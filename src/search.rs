use ldap3::{Ldap, Scope, SearchEntry};
use tracing::debug;

use crate::config::Config;
use crate::error::LdapError;
use crate::model::{Group, User};

/// Search for user in AD by UPN and return attr
/// Returns None if no match
pub(crate) async fn search_user(
    ldap: &mut Ldap,
    config: &Config,
    username: &str,
) -> Result<Option<User>, LdapError> {
    debug!("searching for user {}", username);

    // filter find upn userPrincipalName is the AD attr holding "example.org.uk"
    let filter = format!("(&(objectClass=person)(sAMAccountName={}))", username);

    // vec to hold the AD attr
    let attrs = vec![
        "sAMAccountName",    // usrname
        "userPrincipalName", // full upn
        "displayName",       // name
        "mail",              // email addr
        "memberOf",          // list of group DNs for usr
    ];

    let (entries, _result) = ldap
        .search(&config.base_dn, Scope::Subtree, &filter, attrs)
        .await?
        .success()
        .map_err(|e| LdapError::Search(e.to_string()))?;

    // AD returns only one entry for sAMAccountName search
    debug!("search returned {} entries", entries.len());
    let entry = match entries.into_iter().next() {
        Some(e) => SearchEntry::construct(e),
        None => return Ok(None),
    };

    let username = entry
        .attrs
        .get("sAMAccountName")
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_default();

    let upn_val = entry
        .attrs
        .get("userPrincipalName")
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_default();

    let display_name = entry
        .attrs
        .get("displayName")
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_default();

    let email = entry
        .attrs
        .get("mail")
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_default();

    let groups = entry
        .attrs
        .get("memberOf")
        .map(|dns| dns.iter().map(|dn| parse_group_dn(dn)).collect())
        .unwrap_or_default();

    Ok(Some(User {
        username,
        upn: upn_val,
        display_name,
        email,
        groups,
    }))
}

/// Parse a group DN like "CN=GroupName,OU=Groups,DC=example,DC=org,DC=com"
/// and return a Group with the CN as the name
fn parse_group_dn(dn: &str) -> Group {
    let name = dn
        .split(',')
        .find(|part| part.to_uppercase().starts_with("CN="))
        .map(|part| part[3..].to_string())
        .unwrap_or_else(|| dn.to_string());

    Group {
        name,
        dn: dn.to_string(),
    }
}
