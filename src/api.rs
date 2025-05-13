// use bigdecimal::BigDecimal;
use chrono::{NaiveDate, NaiveTime};
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


// User Profile Data ---
#[derive(Debug, Serialize, Deserialize)]
pub struct UserProfileData {
    // Note: Email is read-only by profile update, password isn't sent here
    pub user_id: Uuid,
    pub email: String, // Include email for display
    pub first_name: String,
    pub surname: String,
    pub gender: Option<String>,
    pub phone: Option<String>,
    pub dob: Option<String>, // Consider using a proper Date type later
    pub stripe_payment_method_id: Option<String>, // Could be null
    pub email_verified: bool,
    // pub waiver_id: Option<Uuid>, // Could be null
    pub photo_id: Option<String>, // Could be null
    pub address: Option<String>,
    pub suburb: Option<String>,
    pub emergency_name: Option<String>,
    pub emergency_relationship: Option<String>,
    pub emergency_phone: Option<String>,
    pub emergency_medical: Option<String>,
    pub belt_size: Option<String>,
    pub uniform_size: Option<String>,
    pub member_number: Option<String>, // Could be null
    pub contracted_until: Option<String>, // Date stored as timestamp or similar in DB
}

#[derive(Debug, Serialize)]
pub struct GetUserProfileResponse {
    pub success: bool,
    pub error_message: Option<String>,
    pub user_profile: Option<UserProfileData>,
}


// User Profile Update Request ---
#[derive(Debug, Deserialize)]
pub struct UpdateUserProfileRequest {
    // User ID isn't needed in the request body as it comes from the session
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
    pub belt_size: Option<String>,
    pub uniform_size: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UpdateUserProfileResponse {
    pub success: bool,
    pub error_message: Option<String>,
}


// Password Change Request ---
#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Serialize)]
pub struct ChangePasswordResponse {
    pub success: bool,
    pub error_message: Option<String>,
}


#[derive(Debug, Serialize)]
pub struct GetWaiverResponse {
    pub success: bool,
    pub error_message: Option<String>,
    pub waiver: Option<String>,
    pub waiver_id: Option<Uuid>,
}

#[derive(Deserialize)]
pub struct AcceptWaiverRequest {
    pub waiver_id: Uuid, // The ID of the waiver the user accepted
}

#[derive(Serialize)]
pub struct AcceptWaiverResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}


// Assuming you have a struct for the waiver creation request
#[derive(Deserialize)]
pub struct CreateWaiverRequest {
    pub title: String, // The content of the new waiver
    pub content: String, // The content of the new waiver
}

// Assuming you have a struct for the waiver creation response
#[derive(Serialize)]
pub struct CreateWaiverResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Uuid>, // Return the ID of the newly created waiver
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

#[derive(Deserialize, Serialize)]

pub enum ClassFrequencyType {
    OneOff,
    Weekly,
    Fortnightly,
    Monthly,
    Yearly,
}

pub struct ClassFrequency {
    pub frequency: i32,
    pub start_date: NaiveDate,
    pub end_date: NaiveDate,
    pub start_time: NaiveTime,
    pub end_time: NaiveTime,
}

#[derive(Deserialize)]
pub struct ClassFrequencyRequest {
    pub frequency: i32,
    pub start_date: String,
    pub end_date: String,
    pub start_time: String,
    pub end_time: String,
}

// Assuming you have a struct for the class creation request
#[derive(Deserialize)]
pub struct CreateClassRequest {
    pub title: String, 
    pub description: String, 
    pub frequency: Vec<ClassFrequencyRequest>,
    pub venue_id: Uuid,
    pub notify_booking: bool,
    pub capacity: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub price: Option<String>,
    pub grading_ids: Vec<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub waiver_id: Option<Uuid>,
    pub publish_mode: i32,
    pub style_ids: Vec<Uuid>,
}

// Struct for the JSON response after trying to create a class
#[derive(Debug, Serialize)] // Derive Serialize for sending JSON
pub struct CreateClassResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")] // Optional field
    pub class_id: Option<Uuid>, // Return the ID of the created class on success
    #[serde(skip_serializing_if = "Option::is_none")] // Optional field
    pub error_message: Option<String>, // Return error message on failure
}