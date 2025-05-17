use actix_web::{
    dev::Payload, error::ErrorUnauthorized, error::ErrorInternalServerError, FromRequest, HttpRequest,
};
use futures_util::future::{ready, Ready};
use std::sync::Arc;
use uuid::Uuid;

use crate::state::StoreStateManager;

// Extractor for authenticated users
pub struct LoggedUser {
    pub user_id: Uuid,
    pub session_token: String,     // Added session_token field
    pub expire_ts: i64,
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
        let session_cookie = req.cookie("session");
        let user_id_cookie = req.cookie("user_id");
        
        // Validate everything
        match (session_cookie, user_id_cookie) {
            ( Some(session_cookie), Some(user_id_cookie) ) => {
                // Both cookies found, now try to parse the user_id
                match user_id_cookie.value().parse::<Uuid>() {
                    Ok(user_id) => {
                        // Both cookies are present and user_id is a valid Uuid
                        // We successfully extracted the necessary info synchronously.
                        // Actual session validity is checked in the handler via validate().
                        ready(Ok(LoggedUser {
                            user_id, // Store the parsed Uuid
                            session_token: session_cookie.value().to_owned(),
                            expire_ts: 0
                        }))
                    },
                    Err(e) => {
                        // user_id cookie exists, but its value is not a valid Uuid format
                        tracing::warn!("Invalid user_id cookie format received: {:?}", e);
                        ready(Err(ErrorUnauthorized("Invalid authentication token format"))) // Indicate format issue
                    }
                }
            }
            // If either cookie is missing, return an Unauthorized error immediately
            _ => {
                tracing::debug!("Session or user_id cookie missing.");
                ready(Err(ErrorUnauthorized("Authentication credentials missing"))) // Indicate missing credentials
            }
        }
    }
}

// Helper method to validate the session in the handler
impl LoggedUser {
    pub async fn validate(&mut self, state: &Arc<StoreStateManager>  ) -> Result<Uuid, actix_web::Error> {
        let verification_result = state.db.verify_session(self.user_id, &self.session_token).await;
        
        match verification_result {
            Ok((true, expires_ts_millis)) => {
                // Session is valid and matches the user_id, and we got the expiry timestamp in milliseconds
                tracing::debug!("Session valid for user_id: {}, expires at (millis): {}", self.user_id, expires_ts_millis);
                self.expire_ts = expires_ts_millis; // Store the fetched expiry timestamp (convert i64 to CqlTimestamp)
                Ok(self.user_id) // Return the successfully validated user_id
            }
            Ok((false, _)) => {
                // Database call succeeded, but the session verification failed (invalid token for user, etc.)
                tracing::debug!("Session verification failed for user_id: {}", self.user_id);
                Err(ErrorUnauthorized("Invalid or expired session"))
            }
            Err(app_err) => {
                // A database error occurred during verification
                tracing::error!("Database error during session verification for user_id {}: {:?}", self.user_id, app_err);
                Err(ErrorInternalServerError(app_err))
            }
        }
    }
}
