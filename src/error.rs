use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database execution error: {0}")]
    DatabaseExecution(#[from] scylla::errors::ExecutionError),

    #[error("Database result error: {0}")]
    DatabaseIntoRows(#[from] scylla::errors::IntoRowsResultError),
    
    #[error("Database row error: {0}")]
    DatabaseRows(#[from] scylla::errors::RowsError),

    #[error("Database row error: {0}")]
    DatabaseDeserialization(#[from] scylla::errors::DeserializationError),

    #[error("JSON serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, AppError>;
