/// Parameters for a single SSH connection attempt, built from an incoming
/// API request (either a fresh "test connect" or a reconnect using a saved
/// `ConnectionProfile`).
pub struct ConnectParams {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub key_path: String,
    /// Passphrase for the private key, if any. Only ever held in memory for
    /// the lifetime of the connection attempt — never persisted to disk.
    pub passphrase: Option<String>,
    /// If true, an unknown host key is learned and trusted automatically
    /// instead of the connection being rejected. Defaults to true since this
    /// is a personal desktop tool connecting to the user's own servers.
    pub trust_unknown_hosts: bool,
}
