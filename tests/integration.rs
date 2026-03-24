use amrc_ldap::LdapClient;
use amrc_ldap::config::Config;
use amrc_ldap::config::TlsMode;
use amrc_ldap::model::AuthResult;

#[tokio::test]
async fn test_authenticate_valid_user() {
    dotenvy::dotenv().ok();
    let host = std::env::var("LDAP_HOST").expect("LDAP_HOST not set");
    let base_dn = std::env::var("LDAP_BASE_DN").expect("LDAP_BASE_DN not set");
    let domain = std::env::var("LDAP_DOMAIN").expect("LDAP_DOMAIN not set");
    let username = std::env::var("LDAP_TEST_USER").expect("LDAP_TEST_USER not set");
    let password = std::env::var("LDAP_TEST_PASSWORD").expect("LDAP_TEST_PASSWORD not set");

    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .try_init();

    let mut config = Config::new(&host, &base_dn, &domain);
    config.port = std::env::var("LDAP_PORT")
        .unwrap_or("636".to_string())
        .parse()
        .expect("LDAP_PORT must be a number");

    let encrypted = std::env::var("LDAP_ENCRYPTED")
        .unwrap_or("true".to_string())
        .parse::<bool>()
        .expect("LDAP_ENCRYPTED must be true or false");

    config.tls_mode = if encrypted {
        TlsMode::ServerAuth
    } else {
        TlsMode::Plain
    };
    let mut client = LdapClient::connect(config)
        .await
        .expect("failed to connect");

    let result = client
        .authenticate(&username, &password)
        .await
        .expect("auth error");

    println!("{:?}", result);
    assert!(matches!(result, AuthResult::Authenticated(_)));
}

#[tokio::test]
async fn test_authenticate_invalid_user() {
    dotenvy::dotenv().ok();
    let host = std::env::var("LDAP_HOST").expect("LDAP_HOST not set");
    let base_dn = std::env::var("LDAP_BASE_DN").expect("LDAP_BASE_DN not set");
    let domain = std::env::var("LDAP_DOMAIN").expect("LDAP_DOMAIN not set");
    let username = std::env::var("LDAP_TEST_USER").expect("LDAP_TEST_USER not set");

    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .try_init();

    let mut config = Config::new(&host, &base_dn, &domain);
    config.port = std::env::var("LDAP_PORT")
        .unwrap_or("636".to_string())
        .parse()
        .expect("LDAP_PORT must be a number");

    let encrypted = std::env::var("LDAP_ENCRYPTED")
        .unwrap_or("true".to_string())
        .parse::<bool>()
        .expect("LDAP_ENCRYPTED must be true or false");

    config.tls_mode = if encrypted {
        TlsMode::ServerAuth
    } else {
        TlsMode::Plain
    };
    let mut client = LdapClient::connect(config)
        .await
        .expect("failed to connect");

    let result = client
        .authenticate(&username, "IncorrectPassword")
        .await
        .expect("auth error");

    println!("{:?}", result);
    assert!(matches!(result, AuthResult::InvalidCredentials));
}