pub mod state;
pub mod db;
pub mod models;
pub mod error;
pub mod api;
pub mod processor;
pub mod templates;
pub mod server;
pub mod email_sender;
pub mod auth;
pub mod db_migrate;
pub mod payment_plan;
mod stripe_client;
// re-export items if you prefer a flat structure:
pub use db::ScyllaConnector;
pub use error::Result as AppResult;