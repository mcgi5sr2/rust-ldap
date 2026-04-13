use ldap3::{Ldap, Scope, SearchEntry};
use tracing::debug;

use crate::config::Config;
use crate::error::LdapError;
use crate::model::{Group, User};

const USER_ATTRS: &[&str] = &[
    "sAMAccountName",
    "userPrincipalName",
    "displayName",
    "mail",
    "memberOf",
];

/// Escape special characters for use in an LDAP filter value
fn ldap_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '\\' => out.push_str("\\5c"),
            '*'  => out.push_str("\\2a"),
            '('  => out.push_str("\\28"),
            ')'  => out.push_str("\\29"),
            '\0' => out.push_str("\\00"),
            _    => out.push(c),
        }
    }
    out
}

/// Run an LDAP filter and return the first matching entry as a User
async fn search_one(
    ldap: &mut Ldap,
    config: &Config,
    filter: &str,
) -> Result<Option<User>, LdapError> {
    let (entries, _) = ldap
        .search(&config.base_dn, Scope::Subtree, filter, USER_ATTRS.to_vec())
        .await?
        .success()
        .map_err(|e| LdapError::Search(e.to_string()))?;

    debug!("search '{}' returned {} entries", filter, entries.len());

    match entries.into_iter().next() {
        Some(e) => Ok(Some(entry_to_user(SearchEntry::construct(e)))),
        None => Ok(None),
    }
}

fn entry_to_user(entry: SearchEntry) -> User {
    let get = |key: &str| {
        entry
            .attrs
            .get(key)
            .and_then(|v| v.first())
            .cloned()
            .unwrap_or_default()
    };

    let groups = entry
        .attrs
        .get("memberOf")
        .map(|dns| dns.iter().map(|dn| parse_group_dn(dn)).collect())
        .unwrap_or_default();

    User {
        username: get("sAMAccountName"),
        upn: get("userPrincipalName"),
        display_name: get("displayName"),
        email: get("mail"),
        groups,
    }
}

/// Search by sAMAccountName — used internally by auth and publicly via LdapClient
pub(crate) async fn search_by_username(
    ldap: &mut Ldap,
    config: &Config,
    username: &str,
) -> Result<Option<User>, LdapError> {
    debug!("searching by username: {}", username);
    let filter = format!("(&(objectClass=person)(sAMAccountName={}))", ldap_escape(username.trim()));
    search_one(ldap, config, &filter).await
}

/// Search by mail attribute
pub(crate) async fn search_by_mail(
    ldap: &mut Ldap,
    config: &Config,
    mail: &str,
) -> Result<Option<User>, LdapError> {
    debug!("searching by mail: {}", mail);
    let filter = format!("(&(objectClass=person)(mail={}))", ldap_escape(mail.trim()));
    search_one(ldap, config, &filter).await
}

pub(crate) async fn search_by_display_name(
    ldap: &mut Ldap,
    config: &Config,
    name: &str,
) -> Result<Option<User>, LdapError> {
    let escaped = ldap_escape(name.trim());
    debug!("searching by display name: {}", escaped);
    let filter = format!("(&(objectClass=person)(displayName={}))", escaped);
    search_one(ldap, config, &filter).await
}

/// Try sAMAccountName → mail → displayName, return first match
pub(crate) async fn search_by_any(
    ldap: &mut Ldap,
    config: &Config,
    query: &str,
) -> Result<Option<User>, LdapError> {
    debug!("searching by any: {}", query);
    if let Some(user) = search_by_username(ldap, config, query).await? {
        return Ok(Some(user));
    }
    if let Some(user) = search_by_mail(ldap, config, query).await? {
        return Ok(Some(user));
    }
    search_by_display_name(ldap, config, query).await
}

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
