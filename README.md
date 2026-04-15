# rust-ldap

A Rust library for authenticating users against LDAP/Active Directory servers.

Supports:
- **Microsoft Active Directory** via standard LDAPS or plain LDAP
- **Google Workspace LDAP** via mutual TLS with a client certificate

## Usage

```rust
use rust_ldap::LdapClient;
use rust_ldap::config::{Config, TlsMode};
use rust_ldap::model::AuthResult;

#[tokio::main]
async fn main() {
    let mut config = Config::new(
        "your.ldap.server",
        "OU=Users,DC=example,DC=com",
        "example.com",
    );
    config.port = 389;
    config.tls_mode = TlsMode::Plain;

    let mut client = LdapClient::connect(config).await.expect("failed to connect");

    match client.authenticate("username", "password").await.expect("auth error") {
        AuthResult::Authenticated(user) => {
            println!("Welcome, {}!", user.display_name);
            println!("Groups: {:?}", user.groups);
            println!("In admin group: {}", user.is_in_group("Administrators"));
        }
        AuthResult::InvalidCredentials => println!("Wrong password"),
        AuthResult::UserNotFound => println!("User not found"),
    }
}
```

## Configuration

| Field | Description | Default |
|-------|-------------|---------|
| `host` | LDAP server hostname | required |
| `base_dn` | Base DN to search for users | required |
| `default_domain` | Domain appended to bare usernames | required |
| `port` | LDAP server port | `636` |
| `tls_mode` | TLS mode (see below) | `ServerAuth` |

### TLS Modes

- `TlsMode::Plain` — no encryption (port 389)
- `TlsMode::ServerAuth` — standard LDAPS, server certificate verified (port 636)
- `TlsMode::MutualAuth { cert_path, key_path }` — mutual TLS, presents a client certificate (Google Workspace LDAP)

## Authentication

`authenticate(username, password)` returns `Result<AuthResult, LdapError>`:

- `AuthResult::Authenticated(User)` — credentials valid, returns user attributes and group memberships
- `AuthResult::InvalidCredentials` — wrong password
- `AuthResult::UserNotFound` — username does not exist

If the LDAP search for user attributes fails, authentication still succeeds and a basic `User` is returned with the username and UPN populated.

## Running the Example

See [examples/auth.rs](examples/auth.rs) — edit the connection details at the top and run:

```
cargo run --example auth
```

## Running Tests

Integration tests require a live LDAP server. Create a `.env` file:

```
LDAP_HOST=your.ldap.server
LDAP_BASE_DN=OU=Users,DC=example,DC=com
LDAP_DOMAIN=example.com
LDAP_PORT=389
LDAP_ENCRYPTED=false
LDAP_TEST_USER=your_username
LDAP_TEST_PASSWORD=your_password
```

Then run:

```
cargo test --test integration
```
