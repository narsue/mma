pub mod state;
pub mod db;
pub mod models;
pub mod error;
pub mod api;
pub mod processor;
// re-export items if you prefer a flat structure:
pub use db::ScyllaConnector;
pub use error::Result as AppResult;