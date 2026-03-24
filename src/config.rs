// connecting to an Active Directory server
use serde::Deserialize;
use std::path::PathBuf;

// Howto establish TLS conn to LDAP server
#[derive(Debug, Clone, Deserialize)]
pub enum TlsMode {
    // no encryption
    Plain,

    // verify the server cert (MS AD)
    ServerAuth,

    // Mutual TLS present client cert too (G Workspace LDAP)
    MutualAuth {
        // Path to client cert (.crt) downloaded from Google Admin
        cert_path: PathBuf,
        // PAth to client priv key (.key) downloaded from Google Admin
        key_path: PathBuf,
    },
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    //hostname or ip
    pub host: String,
    // 636 for TLS or 389 which is bad
    pub port: u16,
    //base domain name
    pub base_dn: String,

    // default domain to append to usrnames upn
    pub default_domain: String,

    // other more exotic domain names, like upn.org.uk
    pub additional_domains: Vec<String>,

    // add TLS!!
    pub tls_mode: TlsMode,
}

impl Config {
    //constructor for common single domain cases
    pub fn new(host: &str, base_dn: &str, default_domain: &str) -> Self {
        Self {
            host: host.to_string(),
            port: 636,
            base_dn: base_dn.to_string(),
            default_domain: default_domain.to_string(),
            additional_domains: Vec::new(),
            tls_mode: TlsMode::ServerAuth,
        }
    }

    // build full LDAPs URL host to port
    pub(crate) fn ldap_url(&self) -> String {
        let scheme = match self.tls_mode {
            TlsMode::Plain => "ldap",
            _ => "ldaps",
        };
        format!("{}://{}:{}", scheme, self.host, self.port)
    }

    // take usrname sans DN and return full UPN
    pub(crate) fn to_upn(&self, username: &str) -> String {
        if username.contains('@') {
            username.to_string()
        } else {
            format!("{}@{}", username, self.default_domain)
        }
    }
}
