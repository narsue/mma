use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct SetGenericResponse {
    pub success: bool,
    pub error_message: Option<String>,
}

// Transaction status update
#[derive(Debug, Deserialize)]
pub struct UpdateClassStatusRequest {
    pub transaction_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub success: bool,
    pub error_message: Option<String>,
    pub token: Option<String>,
    pub user_id: Option<Uuid>,
}



#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    pub first_name: String,
    pub surname: String,
    pub gender: Option<String>,
    pub phone: Option<String>,
    pub dob: Option<String>,
    pub address: Option<String>,
    pub suburb: Option<String>,
    pub emergency_name: Option<String>,
    pub emergency_relationship: Option<String>,
    pub emergency_phone: Option<String>,
    pub emergency_medical: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateUserResponse {
    pub success: bool,
    pub error_message: Option<String>,
    pub user_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct ContactForm {
    pub name: String,
    pub email: String,
    pub message: String,
}