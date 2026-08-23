use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::ssh::SshClient;

/// Keeps active SSH connections alive, keyed by connection profile id, so
/// re-selecting a server in the sidebar re-attaches to the same session
/// instead of logging in again.
#[derive(Clone, Default)]
pub struct SessionManager {
    sessions: Arc<Mutex<HashMap<Uuid, Arc<SshClient>>>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn get(&self, id: Uuid) -> Option<Arc<SshClient>> {
        self.sessions.lock().await.get(&id).cloned()
    }

    pub async fn insert(&self, id: Uuid, client: SshClient) -> Arc<SshClient> {
        let client = Arc::new(client);
        self.sessions.lock().await.insert(id, client.clone());
        client
    }
}
