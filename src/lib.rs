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
// re-export items if you prefer a flat structure:
pub use db::ScyllaConnector;
pub use error::Result as AppResult;