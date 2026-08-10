mod config;
mod ssh;

use anyhow::Result;
use config::Config;
use ssh::SshClient;

#[tokio::main]
async fn main() -> Result<()> {
    // Load SSH_* variables from a local .env file, if present.
    dotenvy::dotenv().ok();

    let config = Config::from_env()?;

    println!(
        "Connecting to {}@{}:{}...",
        config.username, config.host, config.port
    );
    let mut client = SshClient::connect(&config).await?;
    println!("Connected.");

    let command = "echo hello from remote host";
    let output = client.exec(command).await?;

    println!("--- exit status: {} ---", output.exit_status);
    if !output.stdout.is_empty() {
        print!("{}", output.stdout);
    }
    if !output.stderr.is_empty() {
        eprint!("{}", output.stderr);
    }

    println!("--- opening interactive shell (type 'exit' or Ctrl-D to leave) ---");
    client.interactive_shell().await?;

    client.disconnect().await?;

    Ok(())
}
