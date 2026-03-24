use ldap3::{Ldap, LdapConnAsync, LdapConnSettings};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;
use tracing::debug;

use crate::config::{Config, TlsMode};
use crate::error::LdapError;

/// Active connection to the LDAP server
pub struct LdapClient {
    pub(crate) ldap: Ldap,
    pub(crate) config: Config,
}

impl LdapClient {
    /// TLS  connection tot he LDAP server
    /// MS AD standard LDAPS conn
    /// G Workspace, adds client cert
    pub async fn connect(config: Config) -> Result<Self, LdapError> {
        let settings = match &config.tls_mode {
            TlsMode::Plain => {
                debug!("connecting to {} (server auth)", config.ldap_url());
                LdapConnSettings::new()
            }
            TlsMode::ServerAuth => {
                debug!("connecting to {} (server auth)", config.ldap_url());
                LdapConnSettings::new()
            }
            TlsMode::MutualAuth {
                cert_path,
                key_path,
            } => {
                debug!("connecting to {} (mutual TLS)", config.ldap_url());
                // load client cert
                let cert_pem =
                    std::fs::read(cert_path).map_err(|e| LdapError::Connection(e.to_string()))?;
                let key_pem =
                    std::fs::read(key_path).map_err(|e| LdapError::Connection(e.to_string()))?;

                let certs: Vec<CertificateDer<'static>> =
                    rustls_pemfile::certs(&mut cert_pem.as_slice())
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|e| LdapError::Connection(e.to_string()))?;

                let key: PrivateKeyDer<'static> =
                    rustls_pemfile::private_key(&mut key_pem.as_slice())
                        .map_err(|e| LdapError::Connection(e.to_string()))?
                        .ok_or_else(|| LdapError::Connection("no private key found".to_string()))?;

                let mut root_store = RootCertStore::empty();
                for cert in rustls_native_certs::load_native_certs().certs {
                    root_store.add(cert).ok();
                }

                let client_config = ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_client_auth_cert(certs, key)
                    .map_err(|e| LdapError::Connection(e.to_string()))?;

                LdapConnSettings::new().set_config(Arc::new(client_config))
            }
        };

        let (conn, ldap) = LdapConnAsync::with_settings(settings, &config.ldap_url())
            .await
            .map_err(|e| LdapError::Connection(e.to_string()))?;

        // drive conn to vg task to avoid conn stall
        ldap3::drive!(conn);

        debug!("connected to {}", config.ldap_url());

        Ok(Self { ldap, config })
    }
}
