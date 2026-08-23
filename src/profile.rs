use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionProfile {
    pub id: Uuid,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub key_path: String,
}

/// Persists connection profiles as a JSON array on disk, guarded by a mutex
/// since the HTTP handlers may read/write it from concurrent requests.
pub struct ProfileStore {
    path: PathBuf,
    profiles: Mutex<Vec<ConnectionProfile>>,
}

impl ProfileStore {
    pub fn load(path: PathBuf) -> Result<Self> {
        let profiles = if path.exists() {
            let raw = fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            serde_json::from_str(&raw)
                .with_context(|| format!("failed to parse {}", path.display()))?
        } else {
            Vec::new()
        };

        Ok(Self {
            path,
            profiles: Mutex::new(profiles),
        })
    }

    pub fn list(&self) -> Vec<ConnectionProfile> {
        self.profiles.lock().unwrap().clone()
    }

    pub fn get(&self, id: Uuid) -> Option<ConnectionProfile> {
        self.profiles
            .lock()
            .unwrap()
            .iter()
            .find(|p| p.id == id)
            .cloned()
    }

    pub fn add(&self, profile: ConnectionProfile) -> Result<()> {
        let mut profiles = self.profiles.lock().unwrap();
        profiles.push(profile);
        self.persist(&profiles)
    }

    fn persist(&self, profiles: &[ConnectionProfile]) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let raw = serde_json::to_string_pretty(profiles)?;
        fs::write(&self.path, raw)
            .with_context(|| format!("failed to write {}", self.path.display()))?;
        Ok(())
    }
}

/// Default location for the profile store: `~/.webconsole/profiles.json`.
pub fn default_store_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".webconsole").join("profiles.json")
}
