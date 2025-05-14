use std::sync::Arc;
use uuid::Uuid;

use crate::db::{ScyllaConnector, verify_password};
use crate::error::{AppError, Result};

#[derive(Debug, Clone)]
pub struct StoreStateManager {
    pub db: Arc<ScyllaConnector>,
    // stock_cache: DashMap<String, Arc<RwLock<StockLevel>>>,
    // transaction_cache: DashMap<Uuid, (String, TransactionStatus)>,
}

impl StoreStateManager {
    pub fn new(db: Arc<ScyllaConnector>) -> Self {
        Self {
            db,
            // stock_cache: DashMap::new(),
            // transaction_cache: DashMap::new(),
        }
    }

    pub async fn authenticate_user(
        &self,
        email: &String,
        password: &String,
        ip_address: Option<String>,
        user_agent: Option<String>
    ) -> Result<(Uuid, String)> {
        // Query the database for the user with the provided email
        let user_result = self.db.get_user_by_email(&email).await?;
        
        match user_result {
            Some((user_id, stored_hash)) => {
                // Verify password using Argon2
                if !verify_password(password, &stored_hash)? {
                    return Err(AppError::Internal(String::from("Invalid credentials")));
                }
                
                // Create a new session (24-hour duration)
                let session_token = self.db.create_session(&user_id, ip_address, user_agent, 24).await?;
                
                Ok((user_id, session_token))
            },
            None => Err(AppError::Internal(String::from("User not found")))
        }
    }

}