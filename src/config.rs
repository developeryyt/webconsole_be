use anyhow::{Context, Result, bail};
use std::env;

/// How to authenticate with the SSH server.
pub enum AuthMethod {
    Password(String),
    PrivateKey {
        private_key_path: String,
        passphrase: Option<String>,
    },
}

pub struct Config {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: AuthMethod,
    /// If true, host keys not yet in `~/.ssh/known_hosts` are learned and
    /// accepted automatically (trust-on-first-use) instead of being rejected.
    pub trust_unknown_hosts: bool,
}

impl Config {
    /// Loads connection settings from environment variables.
    ///
    /// Required:
    ///   SSH_HOST, SSH_USERNAME
    /// Optional:
    ///   SSH_PORT (default 22)
    ///   SSH_AUTH_METHOD = "key" (default) | "password"
    ///   SSH_TRUST_UNKNOWN_HOSTS = "true" | "false" (default "false")
    /// For SSH_AUTH_METHOD=key:
    ///   SSH_PRIVATE_KEY_PATH (required), SSH_PRIVATE_KEY_PASSPHRASE (optional)
    /// For SSH_AUTH_METHOD=password:
    ///   SSH_PASSWORD (required)
    pub fn from_env() -> Result<Self> {
        let host = env::var("SSH_HOST").context("SSH_HOST is not set")?;
        let port = env::var("SSH_PORT")
            .unwrap_or_else(|_| "22".to_string())
            .parse::<u16>()
            .context("SSH_PORT must be a valid port number")?;
        let username = env::var("SSH_USERNAME").context("SSH_USERNAME is not set")?;

        let auth_method = env::var("SSH_AUTH_METHOD").unwrap_or_else(|_| "key".to_string());
        let auth = match auth_method.as_str() {
            "password" => {
                let password = env::var("SSH_PASSWORD").context("SSH_PASSWORD is not set")?;
                AuthMethod::Password(password)
            }
            "key" => {
                let private_key_path =
                    env::var("SSH_PRIVATE_KEY_PATH").context("SSH_PRIVATE_KEY_PATH is not set")?;
                let passphrase = env::var("SSH_PRIVATE_KEY_PASSPHRASE").ok();
                AuthMethod::PrivateKey {
                    private_key_path,
                    passphrase,
                }
            }
            other => bail!("unknown SSH_AUTH_METHOD '{other}', expected 'password' or 'key'"),
        };

        let trust_unknown_hosts = env::var("SSH_TRUST_UNKNOWN_HOSTS")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        Ok(Self {
            host,
            port,
            username,
            auth,
            trust_unknown_hosts,
        })
    }
}
