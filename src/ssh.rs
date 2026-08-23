use anyhow::{Context, Result, bail};
use russh::client::{self, Handle, Msg};
use russh::keys::known_hosts::learn_known_hosts;
use russh::keys::ssh_key::PublicKey;
use russh::keys::{PrivateKeyWithHashAlg, check_known_hosts, load_secret_key};
use russh::{Channel, ChannelMsg, Disconnect};
use std::sync::Arc;

use crate::config::ConnectParams;

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
                    "host key for {}:{} is not in known_hosts; set trust_unknown_hosts \
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
    /// Opens a TCP connection, performs the SSH handshake, and authenticates
    /// using the private key at `params.key_path`.
    pub async fn connect(params: &ConnectParams) -> Result<Self> {
        let ssh_config = Arc::new(client::Config::default());
        let handler = ClientHandler {
            host: params.host.clone(),
            port: params.port,
            trust_unknown_hosts: params.trust_unknown_hosts,
        };

        let mut handle = client::connect(ssh_config, (params.host.as_str(), params.port), handler)
            .await
            .with_context(|| format!("failed to connect to {}:{}", params.host, params.port))?;

        Self::authenticate(&mut handle, params).await?;

        Ok(Self { handle })
    }

    async fn authenticate(handle: &mut Handle<ClientHandler>, params: &ConnectParams) -> Result<()> {
        let key = load_secret_key(&params.key_path, params.passphrase.as_deref())
            .with_context(|| format!("failed to load private key at {}", params.key_path))?;

        // RSA keys need a hash algorithm negotiated with the server; other key
        // types ignore it. See `PrivateKeyWithHashAlg` docs for details.
        let hash_alg = match handle.best_supported_rsa_hash().await {
            Ok(Some(alg)) => alg,
            _ => None,
        };
        let key_with_alg = PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg);

        let auth_result = handle
            .authenticate_publickey(&params.username, key_with_alg)
            .await
            .context("public key authentication failed")?;

        if !auth_result.success() {
            bail!("authentication failed for user '{}'", params.username);
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

    /// Opens a PTY-backed remote shell channel. The caller (the WebSocket
    /// handler) is responsible for bridging bytes between this channel and
    /// the browser's terminal.
    pub async fn open_shell(&self) -> Result<Channel<Msg>> {
        let channel = self
            .handle
            .channel_open_session()
            .await
            .context("failed to open channel")?;

        channel
            .request_pty(false, "xterm-256color", 120, 30, 0, 0, &[])
            .await
            .context("failed to request a pty")?;
        channel
            .request_shell(false)
            .await
            .context("failed to request a shell")?;

        Ok(channel)
    }

    pub async fn disconnect(&self) -> Result<()> {
        self.handle
            .disconnect(Disconnect::ByApplication, "", "English")
            .await
            .context("failed to disconnect cleanly")?;
        Ok(())
    }
}
