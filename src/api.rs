use bigdecimal::BigDecimal;
use chrono::{NaiveDate, NaiveTime};
use scylla::DeserializeRow;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::stripe_client::PaymentMethod;

#[derive(Debug, Serialize)]
pub struct SetGenericResponse {
    pub success: bool,
    pub error_message: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct GenericResponse {
    pub success: bool,
    pub error_message: Option<String>,
    pub message: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct GenericSuccessResponse {
    pub success: bool,
}

// Transaction status update
#[derive(Debug, Deserialize)]
pub struct UpdateClassStatusRequest {
    pub transaction_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginResponse {
    pub success: bool,
    pub error_message: Option<String>,
    pub token: Option<String>,
    pub logged_user_id: Option<Uuid>,
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
    pub email: Option<String>, // Include email for display
    pub first_name: String,
    pub surname: String,
    pub gender: Option<String>,
    pub phone: Option<String>,
    pub dob: Option<String>, // Consider using a proper Date type later
    pub stripe_payment_method_ids: Vec<String>, // Could be null
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
    pub user_id: Uuid,
    pub first_name: String,
    pub surname: String,
    pub email: Option<String>,
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

#[derive(Debug, Deserialize)]
pub struct UserIdRequest {
    pub user_id: Uuid,
}




#[derive(Debug, Deserialize)]
pub struct UserInviteRequest {
    pub user_id: Uuid,
    pub email: String,
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

#[derive(Debug, Clone, Serialize)]
pub struct ClassFrequency {
    pub frequency: i32,
    pub start_date: NaiveDate,
    pub end_date: NaiveDate,
    pub start_time: NaiveTime,
    pub end_time: NaiveTime,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClassFrequencyId {
    pub class_frequency_id: Uuid,
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

#[derive(Deserialize)]
pub struct ClassFrequencyIdRequest {
    pub class_frequency_id: Option<Uuid>,
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


// Assuming you have a struct for the class creation request
#[derive(Deserialize)]
pub struct UpdateClassRequest {
    pub class_id: Uuid,

    pub title: String, 
    pub description: String, 
    pub frequency: Vec<ClassFrequencyIdRequest>,
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
    pub free_lessons: Option<i32>, // Assuming this is a timestamp
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

#[derive(Debug, Clone, Serialize)]
pub struct ClassData {
    pub class_id: Uuid,
    pub venue_id: Uuid,
    pub waiver_id: Option<Uuid>, // Assuming waiver_id can be null
    pub capacity: i32,
    pub publish_mode: i32,
    pub price: Option<BigDecimal>, // Assuming price can be null
    pub notify_booking: bool,
    pub title: String,
    pub description: String,
    pub frequency: Vec<ClassFrequencyId>,
    pub styles: Vec<Uuid>,
    pub grades: Vec<Uuid>,
    pub free_lessons: Option<i32>, // Assuming this is a timestamp
}


#[derive(Debug, Clone, Serialize, Deserialize, DeserializeRow)]
pub struct VenueData {
    pub venue_id: Uuid,
    pub title: String,
    pub description: Option<String>,
    pub address: Option<String>,
    pub suburb: Option<String>,
    pub state: Option<String>,
    pub postcode: Option<String>,
    pub country: Option<String>,
    pub latitude: Option<BigDecimal>,
    pub longitude: Option<BigDecimal>,
    pub contact_phone: Option<String>,
}

//CreateVenueRequest
#[derive(Deserialize)]
pub struct CreateVenueRequest {
    pub title: String,
    pub description: Option<String>,
    pub address: Option<String>,
    pub suburb: Option<String>,
    pub state: Option<String>,
    pub postcode: Option<String>,
    pub country: Option<String>,
    pub latitude: Option<BigDecimal>,
    pub longitude: Option<BigDecimal>,
    pub contact_phone: Option<String>,
}


// Struct for the JSON response after trying to create a class
#[derive(Debug, Serialize)] // Derive Serialize for sending JSON
pub struct CreateVenueResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")] // Optional field
    pub venue_id: Option<Uuid>, // Return the ID of the created class on success
    #[serde(skip_serializing_if = "Option::is_none")] // Optional field
    pub error_message: Option<String>, // Return error message on failure
}


//CreateVenueRequest
#[derive(Deserialize)]
pub struct CreateStyleRequest {
    pub title: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, DeserializeRow)]
pub struct StyleData {
    pub style_id: Uuid,
    pub title: String,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)] // Derive Serialize for sending JSON
pub struct CreateStyleResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")] // Optional field
    pub style_id: Option<Uuid>, // Return the ID of the created class on success
    #[serde(skip_serializing_if = "Option::is_none")] // Optional field
    pub error_message: Option<String>, // Return error message on failure
}


// Request struct for forgotten password
#[derive(Deserialize)]
pub struct ForgottenPasswordRequest {
    pub email: String,
}

// Response struct for forgotten password
#[derive(Serialize)]
pub struct ForgottenPasswordResponse {
    pub success: bool,
    pub message: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Deserialize)]
pub struct ResetPasswordQuery {
    pub email: String,
    pub code: String,
}

#[derive(Deserialize)]
pub struct ResetPasswordRequest {
    pub email: String,
    pub code: String,
    pub new_password: String,
}

#[derive(Serialize)]
pub struct ResetPasswordResponse {
    pub success: bool,
    pub message: Option<String>,
    pub error_message: Option<String>,
}


// Request structure for user signup
#[derive(Deserialize)]
pub struct SignupRequest {
    pub first_name: String,
    pub surname: String,
    pub email: String,
    pub password: String,
}

// Response structure for signup
#[derive(Serialize)]
pub struct SignupResponse {
    pub success: bool,
    pub message: Option<String>,
    pub error_message: Option<String>,
}

// Query parameters for account verification
#[derive(Deserialize)]
pub struct VerifyAccountQuery {
    pub email: String,
    pub code: String,
}

// Query parameters struct to capture the venue ID
#[derive(Deserialize)]
pub struct GetVenueRequest {
    pub venue_id: Uuid,
}

// Response structure for signup
#[derive(Serialize)]
pub struct GetVenueResponse {
    pub success: bool,
    pub error_message: Option<String>,
    pub venue: Option<VenueData>,
}

// Query parameters struct to capture the class ID
#[derive(Deserialize)]
pub struct GetClassRequest {
    pub class_id: Uuid,
}

// Response structure for signup
#[derive(Serialize)]
pub struct GetClassResponse {
    pub success: bool,
    pub error_message: Option<String>,
    pub class: Option<ClassData>,
}

// Response structure for signup
#[derive(Serialize)]
pub struct GetVenueListResponse {
    pub success: bool,
    pub error_message: Option<String>,
    pub venues: Option<Vec<VenueData>>,
}

// Response structure for signup
#[derive(Serialize)]
pub struct GetStlyeListResponse {
    pub success: bool,
    pub error_message: Option<String>,
    pub styles: Option<Vec<StyleData>>,
}

// Query parameters struct to capture the class ID
#[derive(Deserialize)]
pub struct GetStyleRequest {
    pub style_id: Uuid,
}

// Response structure for signup
#[derive(Serialize)]
pub struct GetStyleResponse {
    pub success: bool,
    pub error_message: Option<String>,
    pub style: Option<StyleData>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SchoolUserId {
    pub school_id: Uuid, // School ID
    pub user_id: Uuid,   // User ID
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DetailedSchoolUserId {
    pub school_id: Uuid, // School ID
    pub user_id: Uuid,   // User ID
    pub school_title: String,
    pub user_name: String,
}

#[derive(Deserialize)]
pub struct GetClassStudentsRequest {
    pub class_id: Uuid,
    pub class_start_ts: i64,
    pub q: Option<String>, // Optional query for filtering students
}

#[derive(Serialize)]
pub struct StudentClassAttendance {
    pub user_id: Uuid,
    pub first_name: String,
    pub surname: String,
    pub img: Option<String>,
    pub attended: bool
}

#[derive(Serialize)]
pub struct GetClassStudentsResponse {
    pub success: bool,
    pub error_message: Option<String>,
    pub students: Option<Vec<StudentClassAttendance>>,
}

#[derive(Deserialize)]
pub struct SetClassStudentsAttendanceRequest {
    pub class_id: Uuid,
    pub class_start_ts: i64,
    pub user_ids: Vec<Uuid>,
    pub present: Vec<bool>,
}

#[derive(Debug, Deserialize)]
pub struct CreateSetupIntentRequest {
    pub customer_email: String,
    pub cardholder_name: String,
}

#[derive(Debug, Serialize)]
pub struct CreateSetupIntentResponse {
    pub client_secret: String,
    pub customer_id: String,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct GetStripeSavedPaymentMethodsResponse {
    pub customer_id: String,
    pub payment_methods: Vec<PaymentMethod>,
}

#[derive(Debug, Serialize, Deserialize)]
// Delete a payment method
pub struct DeletePaymentMethodRequest{
    pub payment_method_id: Option<String>, // ID of the deleted payment method
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PurchasablePaymentPlanData {
    pub payment_plan_id: Uuid,
    pub base_payment_plan_id: Uuid,
    pub grouping_id: i32,
    pub min_age: Option<i32>,
    pub max_age: Option<i32>,
    pub working: Option<bool>,
    pub title: String,
    pub description: String,
    pub cost: BigDecimal,
    pub duration_id: i32,
    pub purchasable: bool, // Indicates if the plan can be purchased
    pub purchasable_message: Option<String>, // Message if not purchasable
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserWithName {
    pub user_id: Uuid,
    pub first_name: String,
    pub surname: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActivePaymentPlanData {
    pub user_payment_plan_id: Uuid,
    pub payment_plan_id: Uuid,
    pub base_payment_plan_id: Uuid,
    pub grouping_id: i32,
    pub min_age: Option<i32>,
    pub max_age: Option<i32>,
    pub working: Option<bool>,
    pub title: String,
    pub description: String,
    pub cost: BigDecimal,
    pub duration_id: i32,
    pub subscribed: bool,
    pub expiration_ts: i64,
    pub members: Vec<UserWithName>,
    pub next_members: Vec<UserWithName>
}

#[derive(Debug, Serialize)]
pub struct PayablePaymentPlansResponse {
    pub success: bool,
    pub payment_plans: Vec<PurchasablePaymentPlanData>,
}

#[derive(Debug, Deserialize)]
pub struct SchoolUpdatePaymentPlanRequest {
    pub base_payment_plan_id: Option<Uuid>,
    pub min_age: Option<i32>,
    pub max_age: Option<i32>,
    pub working: Option<bool>,
    pub title: String,
    pub description: String,
    pub cost: BigDecimal,
    pub duration_id: i32,
    pub grouping_id: i32,
}


#[derive(Debug, Deserialize)]
pub struct UserSubscribePaymentPlan {
    pub base_payment_plan_id: Uuid,
    pub payment_plan_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct ChangeUserSubscribePaymentPlan {
    pub user_payment_plan_id: Uuid,
    pub subscribe: bool
}

#[derive(Serialize)]
pub struct SchoolUser {
    pub user_id: Uuid,
    pub first_name: String,
    pub surname: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub img: Option<String>,
}

#[derive(Serialize)]
pub struct UserSchoolPermission{
    pub club_id: Option<Uuid>,
    pub class_id: Option<Uuid>,
    pub permission: i32
}

#[derive(Serialize)]
pub struct DashStat{
    pub id: Uuid,
    pub id_type: i8,
    pub window: i8,
    pub count: i32,
    pub count_type: i8,
    pub v1: i16,
    pub v2: i16,
}