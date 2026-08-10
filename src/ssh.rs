use anyhow::{Context, Result, bail};
use russh::client::{self, Handle};
use russh::keys::known_hosts::learn_known_hosts;
use russh::keys::ssh_key::PublicKey;
use russh::keys::{PrivateKeyWithHashAlg, check_known_hosts, load_secret_key};
use russh::{ChannelMsg, Disconnect};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::{AuthMethod, Config};

/// Restores the local terminal's normal (cooked) mode when dropped, even if
/// the interactive session below exits early via `?`.
struct RawModeGuard;

impl RawModeGuard {
    fn enable() -> Result<Self> {
        crossterm::terminal::enable_raw_mode().context("failed to enable raw terminal mode")?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_status: u32,
}

/// Handles server-side callbacks during the SSH session, most importantly
/// verifying the server's host key against `~/.ssh/known_hosts`.
struct ClientHandler {
    host: String,
    port: u16,
    trust_unknown_hosts: bool,
}

impl client::Handler for ClientHandler {
    type Error = anyhow::Error;

    async fn check_server_key(&mut self, server_public_key: &PublicKey) -> Result<bool> {
        match check_known_hosts(&self.host, self.port, server_public_key) {
            Ok(true) => Ok(true),
            Ok(false) if self.trust_unknown_hosts => {
                learn_known_hosts(&self.host, self.port, server_public_key)
                    .context("failed to record host key in known_hosts")?;
                println!(
                    "added {}:{} to known_hosts (trust-on-first-use)",
                    self.host, self.port
                );
                Ok(true)
            }
            Ok(false) => {
                bail!(
                    "host key for {}:{} is not in known_hosts; set SSH_TRUST_UNKNOWN_HOSTS=true \
                     to trust it automatically, or add it yourself (e.g. via ssh-keyscan)",
                    self.host,
                    self.port
                );
            }
            Err(err) => {
                bail!(
                    "host key for {}:{} does NOT match the one recorded in known_hosts \
                     (possible man-in-the-middle): {err}",
                    self.host,
                    self.port
                );
            }
        }
    }
}

pub struct SshClient {
    handle: Handle<ClientHandler>,
}

impl SshClient {
    /// Opens a TCP connection, performs the SSH handshake, and authenticates.
    pub async fn connect(config: &Config) -> Result<Self> {
        let ssh_config = Arc::new(client::Config::default());
        let handler = ClientHandler {
            host: config.host.clone(),
            port: config.port,
            trust_unknown_hosts: config.trust_unknown_hosts,
        };

        let mut handle = client::connect(ssh_config, (config.host.as_str(), config.port), handler)
            .await
            .with_context(|| format!("failed to connect to {}:{}", config.host, config.port))?;

        Self::authenticate(&mut handle, config).await?;

        Ok(Self { handle })
    }

    async fn authenticate(handle: &mut Handle<ClientHandler>, config: &Config) -> Result<()> {
        let auth_result = match &config.auth {
            AuthMethod::Password(password) => handle
                .authenticate_password(&config.username, password)
                .await
                .context("password authentication failed")?,
            AuthMethod::PrivateKey {
                private_key_path,
                passphrase,
            } => {
                let key = load_secret_key(private_key_path, passphrase.as_deref())
                    .with_context(|| format!("failed to load private key at {private_key_path}"))?;

                // RSA keys need a hash algorithm negotiated with the server; other key
                // types ignore it. See `PrivateKeyWithHashAlg` docs for details.
                let hash_alg = match handle.best_supported_rsa_hash().await {
                    Ok(Some(alg)) => alg,
                    _ => None,
                };
                let key_with_alg = PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg);

                handle
                    .authenticate_publickey(&config.username, key_with_alg)
                    .await
                    .context("public key authentication failed")?
            }
        };

        if !auth_result.success() {
            bail!("authentication failed for user '{}'", config.username);
        }

        Ok(())
    }

    /// Runs a single command on the remote host and collects its output.
    pub async fn exec(&self, command: &str) -> Result<CommandOutput> {
        let mut channel = self
            .handle
            .channel_open_session()
            .await
            .context("failed to open channel")?;

        channel
            .exec(true, command)
            .await
            .with_context(|| format!("failed to execute command: {command}"))?;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_status = 0u32;

        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, ext: 1 } => stderr.extend_from_slice(&data),
                ChannelMsg::ExitStatus {
                    exit_status: status,
                } => exit_status = status,
                ChannelMsg::Close => break,
                _ => {}
            }
        }

        Ok(CommandOutput {
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            exit_status,
        })
    }

    /// Opens a PTY-backed remote shell and pumps bytes between it and the
    /// local terminal until the remote side closes the channel — the same
    /// experience as running `ssh host` with no command.
    pub async fn interactive_shell(&self) -> Result<()> {
        let channel = self
            .handle
            .channel_open_session()
            .await
            .context("failed to open channel")?;

        let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
        let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string());

        channel
            .request_pty(false, &term, cols as u32, rows as u32, 0, 0, &[])
            .await
            .context("failed to request a pty")?;
        channel
            .request_shell(false)
            .await
            .context("failed to request a shell")?;

        let (mut read_half, write_half) = channel.split();
        let _raw_mode = RawModeGuard::enable()?;

        let mut stdin = tokio::io::stdin();
        let mut stdout = tokio::io::stdout();
        let mut buf = [0u8; 1024];

        loop {
            tokio::select! {
                n = stdin.read(&mut buf) => {
                    let n = n.context("failed to read local stdin")?;
                    if n == 0 {
                        break;
                    }
                    write_half
                        .data_bytes(buf[..n].to_vec())
                        .await
                        .context("failed to send input to remote shell")?;
                }
                msg = read_half.wait() => {
                    match msg {
                        Some(ChannelMsg::Data { data }) => {
                            stdout.write_all(&data).await.context("failed to write remote output")?;
                            stdout.flush().await.context("failed to flush stdout")?;
                        }
                        Some(ChannelMsg::ExtendedData { data, ext: 1 }) => {
                            stdout.write_all(&data).await.context("failed to write remote output")?;
                            stdout.flush().await.context("failed to flush stdout")?;
                        }
                        Some(ChannelMsg::Close) | Some(ChannelMsg::Eof) | None => break,
                        _ => {}
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn disconnect(&mut self) -> Result<()> {
        self.handle
            .disconnect(Disconnect::ByApplication, "", "English")
            .await
            .context("failed to disconnect cleanly")?;
        Ok(())
    }
}
