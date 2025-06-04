use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Database execution error: {0}")]
    DatabaseExecution(#[from] scylla::errors::ExecutionError),

    #[error("Database result error: {0}")]
    DatabaseIntoRows(#[from] scylla::errors::IntoRowsResultError),
    
    #[error("Database row error: {0}")]
    DatabaseRows(#[from] scylla::errors::RowsError),

    #[error("Database Deserialization error: {0}")]
    DatabaseDeserialization(#[from] scylla::errors::DeserializationError),

    #[error("Database prepare error: {0}")]
    DatabasePrepare(#[from] scylla::errors::PrepareError),


    #[error("JSON serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Internal error: {0}")]
    Internal(String),

    #[error("User error: {0}")]
    User(String),

    #[error("User has no credit card, please add one to your account {0}")]
    UserNoCreditCard(String),

    #[error("User must accept waiver {0}")]
    UserWaiverNotAccepted(String),

    #[error("Class is full {0}")]
    ClassIsFull(String),
}

pub type Result<T> = std::result::Result<T, AppError>;
