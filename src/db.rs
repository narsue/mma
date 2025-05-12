use scylla::transport::query_result::FirstRowError;
use scylla::transport::errors::QueryError; // Make sure QueryError is also imported
use scylla::{Session, SessionBuilder};
use std::sync::Arc;
use uuid::Uuid;
use std::time::SystemTime;
use rand::{distributions::Alphanumeric, Rng};
use std::net::IpAddr;
use chrono::{NaiveDate, NaiveTime, DateTime, Duration, Utc};

use crate::error::{AppError, Result};
use crate::api::{UserProfileData, UpdateUserProfileRequest}; // <-- Import new API structs

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};


pub fn hash_password(password: &str) -> Result<String> {
    // Generate a random salt
    let salt = SaltString::generate(&mut OsRng);
    
    // Configure Argon2 with default parameters
    let argon2 = Argon2::default();
    
    // Hash the password
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(format!("Failed to hash password: {}", e)))?
        .to_string();
    
    Ok(password_hash)
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    // Parse the stored password hash
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| AppError::Internal(format!("Invalid password hash format: {}", e)))?;
    
    // Verify the password against the hash
    let result = Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok();
    
    Ok(result)
}



#[derive(Debug, Clone)]
pub struct ScyllaConnector {
    session: Arc<Session>,
}

impl ScyllaConnector {
    pub async fn new(nodes: &[&str]) -> Result<Self> {
        let session = SessionBuilder::new()
            .known_nodes(nodes)
            .user("cassandra", "cassandra")

            .build()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to connect to Scylla: {}", e)))?;
        println!("Connected");
        Ok(Self {
            session: Arc::new(session),
        })
    }
    
    pub async fn init_schema(&self) -> Result<()> {
        // Create keyspace
        self.session
            .query(
                "CREATE KEYSPACE IF NOT EXISTS mma WITH REPLICATION = \
                {'class': 'SimpleStrategy', 'replication_factor': 3}",
                &[],
            )
            .await?;
        println!("Keyspace created");
            
        self.session
            .query(
                "CREATE TABLE IF NOT EXISTS mma.user \
                (user_id uuid, email text, password_hash text, first_name text, surname text, gender text, phone text, dob text, stripe_payment_method_id text, created_ts timestamp, email_verified boolean, waiver_id uuid, photo_id text, address text, suburb text, emergency_name text, emergency_relationship text, emergency_phone text, emergency_medical text, belt_size text, uniform_size text, member_number text, contracted_until date, PRIMARY KEY (user_id))",
                &[],
            )
            .await?;
        println!("User table created");
            

        self.session
        .query(
            "CREATE TABLE IF NOT EXISTS mma.club \
            (club_id uuid, title text, description text, PRIMARY KEY (club_id))",
            &[],
        )
        .await?;
        println!("Club table created");
        

        self.session
        .query(
            "CREATE TABLE IF NOT EXISTS mma.club_user \
            (club_id uuid, user_id uuid, PRIMARY KEY (club_id, user_id))",
            &[],
        )
        .await?;
        println!("Club user table created");

        self.session
        .query(
            "CREATE TABLE IF NOT EXISTS mma.club_class \
            (club_id uuid, class_id uuid, PRIMARY KEY (club_id, class_id))",
            &[],
        )
        .await?;
        println!("Club class table created");

        self.session
            .query(
                "CREATE TABLE IF NOT EXISTS mma.user_permission \
                (user_id uuid, club_id uuid, class_id uuid, permission int, created_ts timestamp, \
                 PRIMARY KEY (user_id, club_id, class_id, permission))",
                &[],
            )
            .await?;
        println!("User permission table created");

        self.session
            .query(
                "CREATE TABLE IF NOT EXISTS mma.waiver \
                (waiver_id uuid, waiver text, created_ts timestamp, \
                 PRIMARY KEY (waiver_id))",
                &[],
            )
            .await?;
        println!("Waiver table created");

        self.session
        .query(
            "CREATE TABLE IF NOT EXISTS mma.class \
            (class_id uuid, title text, style_id uuid, description text, frequency int, start_date date, created_ts timestamp, end_ts timestamp, \
                PRIMARY KEY (class_id))",
            &[],
        )
        .await?;
        println!("Class table created");
        

        self.session
        .query(
            "CREATE TABLE IF NOT EXISTS mma.instructor \
            (user_id uuid, class_id uuid, permission int, created_ts timestamp, \
                PRIMARY KEY (user_id, class_id))",
            &[],
        )
        .await?;
        println!("Instructor table created");

        self.session
        .query(
            "CREATE TABLE IF NOT EXISTS mma.attendance \
            (user_id uuid, class_id uuid, is_instructor boolean, \
                PRIMARY KEY (user_id, class_id))",
            &[],
        )
        .await?;
        println!("Attendance table created");

        self.session
        .query(
            "CREATE TABLE IF NOT EXISTS mma.style \
            (style_id uuid, title text, description text, \
                PRIMARY KEY (style_id))",
            &[],
        )
        .await?;
        println!("Style table created");

        self.session
        .query(
            "CREATE TABLE IF NOT EXISTS mma.grade \
            (grading_id uuid, title text, description text, attendance_req int, rank int, \
                PRIMARY KEY (grading_id))",
            &[],
        )
        .await?;
        println!("Grade table created");


        self.session
        .query(
            "CREATE TABLE IF NOT EXISTS mma.grading_requirement \
            (grading_requirement_id uuid, title text, description text, requirement int, \
                PRIMARY KEY (grading_requirement_id))",
            &[],
        )
        .await?;
        println!("Grading requirement table created");

        self.session
        .query(
            "CREATE TABLE IF NOT EXISTS mma.user_style_grade \
            (style_id uuid, user_id uuid, grading_id uuid, note text, created_ts timestamp, \
                PRIMARY KEY (style_id, user_id, grading_id))",
            &[],
        )
        .await?;
        println!("User style grade table created");


        self.session
        .query(
            "CREATE TABLE IF NOT EXISTS mma.session \
            (session_token text, user_id uuid, created_ts timestamp, expires_ts timestamp, \
             ip_address text, user_agent text, is_active boolean, \
             PRIMARY KEY (session_token))",
            &[],
        )
        .await?;
        println!("Session table created");

        self.session
        .query(
            "CREATE TABLE IF NOT EXISTS mma.user_by_email \
            (email text PRIMARY KEY, user_id uuid)",
            &[],
        )
        .await?;
        println!("Email to user table created");


        println!("Schema initialized");
        Ok(())
    }
    


    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<(Uuid, String)>> {
        // First, get the user_id from the email lookup table
        let email_result = self.session
            .query(
                "SELECT user_id FROM mma.user_by_email WHERE email = ?",
                (email,),
            )
            .await?;
        
        // If we don't find the email, return None
        let user_id = match email_result.first_row() {
            Ok(row) => {
                row.columns[0].as_ref()
                    .and_then(|val| val.as_uuid())
                    .ok_or_else(|| AppError::Internal(format!("Invalid user_id format")))?
            },
            Err(_) => return Ok(None), // Email not found
        };
        
        // Now get the password hash from the user table using the user_id
        let user_result = self.session
            .query(
                "SELECT password_hash FROM mma.user WHERE user_id = ?",
                (user_id,),
            )
            .await?;
        
        // Extract the password hash
        match user_result.first_row() {
            Ok(row) => {
                let password_hash = row.columns[0].as_ref()
                    .and_then(|val| val.as_text())
                    .ok_or_else(|| AppError::Internal(format!("Invalid password_hash format")))?;
                
                Ok(Some((user_id, password_hash.to_string())))
            },
            Err(_) => {
                // This should rarely happen (inconsistent data state)
                Err(AppError::Internal(format!("User found in email table but not in user table")))
            }
        }
    }

    pub async fn create_session(
        &self,
        user_id: Uuid,
        ip_address: Option<String>,
        user_agent: Option<String>,
        duration_hours: i64,
    ) -> Result<String> {
        // Generate a secure random session token
        let session_token: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)  // 64 character token
            .map(char::from)
            .collect();
        
        // Calculate timestamps
        let now = Utc::now();
        let expires = now + Duration::hours(duration_hours);
        
        // Convert to seconds since epoch
        let now_secs = now.timestamp();
        let expires_secs = expires.timestamp();
        
        // Store the session in the database
        self.session
            .query(
                "INSERT INTO mma.session (session_token, user_id, created_ts, expires_ts, ip_address, user_agent, is_active) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    &session_token,
                    user_id,
                    now_secs,
                    expires_secs,
                    ip_address.unwrap_or_default(),
                    user_agent.unwrap_or_default(),
                    true,
                ),
            )
            .await?;
        
        Ok(session_token)
    }

    // Verify a session token and return the user ID if valid
    pub async fn verify_session(&self, session_token: &str) -> Result<Option<Uuid>> {
        println!("Verifying session: {}", session_token);
        let result = self.session
            .query(
                "SELECT user_id, expires_ts, is_active FROM mma.session WHERE session_token = ?",
                (session_token,),
            )
            .await?;
        
        match result.first_row() {
            Ok(row) => {
                // Extract user_id (first column)
                let user_id: Uuid = row.columns[0].as_ref()
                    .and_then(|val| val.as_uuid())
                    .ok_or_else(|| AppError::Internal("Invalid user_id format in session".to_string()))?;
                
                // Extract expires_ts (second column)
                let expires_ts: i64 = row.columns[1].as_ref()
                    .and_then(|val| val.as_bigint())
                    .ok_or_else(|| AppError::Internal("Invalid expires_ts format in session".to_string()))?;
                
                // Extract is_active (third column)
                let is_active: bool = row.columns[2].as_ref()
                    .and_then(|val| val.as_boolean())
                    .ok_or_else(|| AppError::Internal("Invalid is_active format in session".to_string()))?;
                
                let now = Utc::now().timestamp();
                
                // Check if session is valid (not expired and is active)
                if now <= expires_ts && is_active {
                    Ok(Some(user_id))
                } else {
                    // Optionally invalidate expired sessions
                    if now > expires_ts {
                        self.invalidate_session(session_token).await?;
                    }
                    Ok(None)
                }
            },
            Err(_) => Ok(None), // Session not found
        }
    }
    
    // Invalidate a session (logout)
    pub async fn invalidate_session(&self, session_token: &str) -> Result<()> {
        self.session
            .query(
                "UPDATE mma.session SET is_active = false WHERE session_token = ?",
                (session_token,),
            )
            .await?;
        
        Ok(())
    }
    
    // Invalidate all sessions for a user (force logout everywhere)
    pub async fn invalidate_all_user_sessions(&self, user_id: Uuid) -> Result<()> {
        self.session
            .query(
                "UPDATE mma.session SET is_active = false WHERE user_id = ?",
                (user_id,),
            )
            .await?;
        
        Ok(())
    }

    // Add user creation method
    pub async fn create_user(
        &self, 
        email: &str,
        password: &str,
        first_name: &str,
        surname: &str,
        gender: Option<&str>,
        phone: Option<&str>,
        dob: Option<&str>,
        address: Option<&str>,
        suburb: Option<&str>,
        emergency_name: Option<&str>,
        emergency_relationship: Option<&str>,
        emergency_phone: Option<&str>,
        emergency_medical: Option<&str>,
    ) -> Result<Uuid> {
        // Check if email already exists using the email lookup table
        let email_check = self.session
            .query(
                "SELECT user_id FROM mma.user_by_email WHERE email = ?",
                (email,),
            )
            .await?;
        
        if let Ok(_) = email_check.first_row() {
            return Err(AppError::Internal(format!("Email {} is already registered", email)));
        }
        
        // Hash the password
        let password_hash = hash_password(password)?;
        
        // Generate a new user ID
        let user_id = Uuid::new_v4();
        
        // Get current timestamp
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        
        // Insert main user record
        self.session
            .query(
                "INSERT INTO mma.user (user_id, email, password_hash, first_name, surname, gender, phone, dob, \
                 address, suburb, emergency_name, emergency_relationship, emergency_phone, emergency_medical, \
                 created_ts, email_verified) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    user_id,
                    email,
                    &password_hash,
                    first_name,
                    surname,
                    gender.unwrap_or(""),
                    phone.unwrap_or(""),
                    dob.unwrap_or(""),
                    address.unwrap_or(""),
                    suburb.unwrap_or(""),
                    emergency_name.unwrap_or(""),
                    emergency_relationship.unwrap_or(""),
                    emergency_phone.unwrap_or(""),
                    emergency_medical.unwrap_or(""),
                    now,
                    false,
                ),
            )
            .await?;
        
        // Insert into email lookup table
        self.session
            .query(
                "INSERT INTO mma.user_by_email (email, user_id) VALUES (?, ?)",
                (email, user_id),
            )
            .await?;
        
        Ok(user_id)
    }


    // Get User Profile Data by ID ---
    pub async fn get_user_profile(&self, user_id: Uuid) -> Result<Option<UserProfileData>> {
        let result = self.session
            .query(
                "SELECT user_id, email, first_name, surname, gender, phone, dob, \
                stripe_payment_method_id, created_ts, email_verified, waiver_id, \
                photo_id, address, suburb, emergency_name, emergency_relationship, \
                emergency_phone, emergency_medical, belt_size, uniform_size, \
                member_number, contracted_until \
                FROM mma.user WHERE user_id = ?",
                (user_id,),
            )
            .await?;

        match result.first_row() {
            Ok(row) => {
                // Extract each column by index
                // Be careful with types and Optionals
                let user_profile = UserProfileData {
                    user_id: row.columns[0].as_ref().and_then(|v| v.as_uuid()).ok_or_else(|| AppError::Internal("Invalid user_id in DB".to_string()))?,
                    email: row.columns[1].as_ref().and_then(|v| v.as_text()).ok_or_else(|| AppError::Internal("Invalid email in DB".to_string()))?.to_string(),
                    first_name: row.columns[2].as_ref().and_then(|v| v.as_text()).ok_or_else(|| AppError::Internal("Invalid first_name in DB".to_string()))?.to_string(),
                    surname: row.columns[3].as_ref().and_then(|v| v.as_text()).ok_or_else(|| AppError::Internal("Invalid surname in DB".to_string()))?.to_string(),
                    gender: row.columns[4].as_ref().and_then(|v| v.as_text()).map(|s| s.to_string()),
                    phone: row.columns[5].as_ref().and_then(|v| v.as_text()).map(|s| s.to_string()),
                    dob: row.columns[6].as_ref().and_then(|v| v.as_text()).map(|s| s.to_string()),
                    stripe_payment_method_id: row.columns[7].as_ref().and_then(|v| v.as_text()).map(|s| s.to_string()),
                    // Timestamps are often i64 (microseconds since epoch) in Scylla/Cassandra
                    created_ts: row.columns[8].as_ref().and_then(|v| v.as_bigint()).ok_or_else(|| AppError::Internal("Invalid created_ts in DB".to_string()))?,
                    email_verified: row.columns[9].as_ref().and_then(|v| v.as_boolean()).ok_or_else(|| AppError::Internal("Invalid email_verified in DB".to_string()))?,
                    waiver_id: row.columns[10].as_ref().and_then(|v| v.as_uuid()),
                    photo_id: row.columns[11].as_ref().and_then(|v| v.as_text()).map(|s| s.to_string()),
                    address: row.columns[12].as_ref().and_then(|v| v.as_text()).map(|s| s.to_string()),
                    suburb: row.columns[13].as_ref().and_then(|v| v.as_text()).map(|s| s.to_string()),
                    emergency_name: row.columns[14].as_ref().and_then(|v| v.as_text()).map(|s| s.to_string()),
                    emergency_relationship: row.columns[15].as_ref().and_then(|v| v.as_text()).map(|s| s.to_string()),
                    emergency_phone: row.columns[16].as_ref().and_then(|v| v.as_text()).map(|s| s.to_string()),
                    emergency_medical: row.columns[17].as_ref().and_then(|v| v.as_text()).map(|s| s.to_string()),
                    belt_size: row.columns[18].as_ref().and_then(|v| v.as_text()).map(|s| s.to_string()),
                    uniform_size: row.columns[19].as_ref().and_then(|v| v.as_text()).map(|s| s.to_string()),
                    member_number: row.columns[20].as_ref().and_then(|v| v.as_text()).map(|s| s.to_string()),
                    // Dates are often stored as Unix timestamp in Scylla/Cassandra dates
                    contracted_until: row.columns[21].as_ref().and_then(|v| v.as_date()).map(|date| {
                            // Combine the NaiveDate with midnight time (00:00:00)
                            let datetime_at_midnight = date.and_time(NaiveTime::default());
                            // Get the Unix timestamp (seconds since epoch), treating the NaiveDateTime as UTC
                            datetime_at_midnight.timestamp()
                        }),
                };
                Ok(Some(user_profile))
            },
            // Err(FirstRowError::NotFound) => Ok(None), // User not found
            Err(_) => Err(AppError::Internal(format!("Database error"))), // Other database errors
        }
    }

    // Update User Profile ---
    pub async fn update_user_profile(&self, user_id: Uuid, update_data: &UpdateUserProfileRequest) -> Result<()> {
        self.session
            .query(
                "UPDATE mma.user \
                SET first_name = ?, surname = ?, gender = ?, phone = ?, dob = ?, \
                address = ?, suburb = ?, emergency_name = ?, emergency_relationship = ?, \
                emergency_phone = ?, emergency_medical = ?, belt_size = ?, uniform_size = ? \
                WHERE user_id = ?",
                (
                    &update_data.first_name,
                    &update_data.surname,
                    update_data.gender.as_deref().unwrap_or_default(), // Send "" for None
                    update_data.phone.as_deref().unwrap_or_default(),
                    update_data.dob.as_deref().unwrap_or_default(),
                    update_data.address.as_deref().unwrap_or_default(),
                    update_data.suburb.as_deref().unwrap_or_default(),
                    update_data.emergency_name.as_deref().unwrap_or_default(),
                    update_data.emergency_relationship.as_deref().unwrap_or_default(),
                    update_data.emergency_phone.as_deref().unwrap_or_default(),
                    update_data.emergency_medical.as_deref().unwrap_or_default(),
                    update_data.belt_size.as_deref().unwrap_or_default(),
                    update_data.uniform_size.as_deref().unwrap_or_default(),
                    user_id,
                ),
            )
            .await?;
        Ok(())
    }

    // This is separate from get_user_profile for security
    pub async fn get_password_hash(&self, user_id: Uuid) -> Result<Option<String>> {
        let result = self.session
        .query(
            "SELECT password_hash FROM mma.user WHERE user_id = ?",
            (user_id,),
        )
        .await?; // This ? works because QueryError has From<FirstRowError> or is mapped to AppError
    
        match result.first_row() {
            Ok(row) => {
                let password_hash = row.columns[0].as_ref()
                    .and_then(|val| val.as_text())
                    .ok_or_else(|| AppError::Internal(format!("Invalid password_hash format in DB for user {}", user_id)))?;
    
                Ok(Some(password_hash.to_string()))
            },
            Err(e) => {
                use scylla::transport::query_result::FirstRowError; // Import FirstRowError here if not globally used
    
                match e {
                     FirstRowError::RowsEmpty => Ok(None), // Correctly mapped NotFound to Ok(None)
                     _ => {
                          tracing::error!("Unexpected FirstRowError fetching password hash for user {}: {:?}", user_id, e);
                          // Map other FirstRowError types to AppError::Internal as per previous fix
                          Err(AppError::Internal(format!("Data retrieval error: {:?}", e)))
                     }
                 }
            }
        }
    }

    // Update Password Hash by ID ---
    pub async fn update_password_hash(&self, user_id: Uuid, new_password_hash: String) -> Result<()> {
        self.session
            .query(
                "UPDATE mma.user SET password_hash = ? WHERE user_id = ?",
                (&new_password_hash, user_id),
            )
            .await?;
        Ok(())
    }






}
