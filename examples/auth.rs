use amrc_ldap::LdapClient;
use amrc_ldap::config::Config;
use amrc_ldap::config::TlsMode;

#[tokio::main]
async fn main() {
    //configure LDAP here
let ldap_host: &str = "your.ldap.server";
let ldap_base_dn: &str = "OU=Users,DC=example,DC=com";
let ldap_domain: &str = "example.com";
let ldap_port: u16 = 636;
let ldap_encrypted: bool = true;
let ldap_test_user: &str = "test_user";
let ldap_test_password: &str = "test_password";

let mut config = Config::new(&ldap_host, &ldap_base_dn, &ldap_domain);
    config.port = ldap_port;

    let encrypted = ldap_encrypted;

    config.tls_mode = if encrypted {
        TlsMode::ServerAuth
    } else {
        TlsMode::Plain
    };

    let mut client = LdapClient::connect(config)
        .await
        .expect("failed to connect");

    let result = client
        .authenticate(&ldap_test_user, &ldap_test_password)
        .await
        .expect("auth error");

    println!("{:?}", result);
}