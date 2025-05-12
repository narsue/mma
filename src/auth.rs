use actix_web::{
    dev::Payload, error::ErrorUnauthorized, FromRequest, HttpRequest,
};
use futures_util::future::{ready, Ready};
use std::sync::Arc;
use uuid::Uuid;

use crate::state::StoreStateManager;

// Extractor for authenticated users
pub struct LoggedUser {
    pub user_id: Uuid,
    pub session_token: String,     // Added session_token field
    // pub state: Arc<StoreStateManager>, // Added state field
}

// Implementation of FromRequest for LoggedUser
impl FromRequest for LoggedUser {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        // Get the app state
        // let state = req.app_data::<Arc<StoreStateManager>>().cloned();
        
        // Get the session cookie
        let cookie = req.cookie("session");
        
        // Validate everything
        match (cookie) {
            ( Some(cookie)) => {
                // We can't use async in FromRequest with Ready, so we'll
                // validate the session in the handler instead
                ready(Ok(LoggedUser {
                    user_id: Uuid::nil(), // Placeholder, will be validated in handler
                    session_token: cookie.value().to_owned(),
                    // state,
                }))
            }
            _ => ready(Err(ErrorUnauthorized("Authentication required"))),
        }
    }
}

// Helper method to validate the session in the handler
impl LoggedUser {
    pub async fn validate(&mut self, state: &Arc<StoreStateManager>  ) -> Result<Uuid, actix_web::Error> {
        match state.db.verify_session(&self.session_token).await {
            Ok(Some(user_id)) => {
                self.user_id = user_id;
                Ok(user_id)
            }
            _ => Err(ErrorUnauthorized("Invalid or expired session")),
        }
    }
}
