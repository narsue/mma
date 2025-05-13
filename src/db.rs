// use actix_web::http::header::q;
// use argon2::password_hash::Decimal;
// use scylla::transport::query_result::FirstRowError;
// use scylla::transport::errors::QueryError; // Make sure QueryError is also imported
use scylla::client::session::Session;
use scylla::client::session_builder::SessionBuilder;
use scylla::DeserializeRow;

use std::sync::Arc;
use uuid::Uuid;
use std::time::SystemTime;
use rand::{distributions::Alphanumeric, Rng};
// use std::net::IpAddr;
use chrono::{NaiveDate, Utc};
use scylla::value::CqlTimestamp;
 // Import FirstRowError here if not globally used

use crate::error::{AppError, Result, Result as AppResult};
use crate::api::{UserProfileData, UpdateUserProfileRequest}; // <-- Import new API structs

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

#[derive(DeserializeRow)]
struct UserRow {
    user_id: Uuid,           // 0: uuid (PK, assumed non-null by deserializer)
    email: String,           // 1: text (assumed non-null)
    first_name: String,      // 3: text (assumed non-null)
    surname: String,         // 4: text (assumed non-null)
    gender: Option<String>,  // 5: text (nullable)
    phone: Option<String>,   // 6: text (nullable)
    dob: Option<String>,     // 7: text (nullable - consider Date type if stored as such)
    stripe_payment_method_id: Option<String>, // 8: text (nullable)
    email_verified: bool,    // 10: boolean (assumed non-null)
    photo_id: Option<String>,// 11: text (nullable)
    address: Option<String>, // 12: text (nullable)
    suburb: Option<String>,  // 13: text (nullable)
    emergency_name: Option<String>, // 14: text (nullable)
    emergency_relationship: Option<String>, // 15: text (nullable)
    emergency_phone: Option<String>, // 16: text (nullable)
    emergency_medical: Option<String>, // 17: text (nullable)
    belt_size: Option<String>, // 18: text (nullable)
    uniform_size: Option<String>, // 19: text (nullable)
    member_number: Option<String>, // 20: text (nullable)
    contracted_until: Option<NaiveDate>, // 21: date (nullable, maps to NaiveDate)
}



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
            .query_unpaged(
                "CREATE KEYSPACE IF NOT EXISTS mma WITH REPLICATION = \
                {'class': 'SimpleStrategy', 'replication_factor': 3}",
                &[],
            )
            .await?;
        println!("Keyspace created");
            

        self.session
            .query_unpaged(
                "CREATE TABLE IF NOT EXISTS mma.school \
                (super_user_id uuid, school_id uuid, stripe_id text, title text, description text, created_ts timestamp, PRIMARY KEY (school_id))",
                &[],
            )
            .await?;
        println!("school table created");

        self.session
            .query_unpaged(
                "CREATE TABLE IF NOT EXISTS mma.user \
                (user_id uuid, email text, password_hash text, first_name text, surname text, gender text, phone text, dob text, stripe_payment_method_id text, created_ts timestamp, email_verified boolean, photo_id text, address text, suburb text, emergency_name text, emergency_relationship text, emergency_phone text, emergency_medical text, belt_size text, uniform_size text, member_number text, contracted_until date, PRIMARY KEY (user_id))",
                &[],
            )
            .await?;
        println!("User table created");
            

        self.session
        .query_unpaged(
            "CREATE TABLE IF NOT EXISTS mma.club \
            (club_id uuid, school_id uuid, title text, description text, PRIMARY KEY (club_id))",
            &[],
        )
        .await?;
        println!("Club table created");
        

        self.session
        .query_unpaged(
            "CREATE TABLE IF NOT EXISTS mma.club_user \
            (club_id uuid, user_id uuid, PRIMARY KEY (club_id, user_id))",
            &[],
        )
        .await?;
        println!("Club user table created");

        self.session
        .query_unpaged(
            "CREATE TABLE IF NOT EXISTS mma.club_class \
            (club_id uuid, class_id uuid, PRIMARY KEY (club_id, class_id))",
            &[],
        )
        .await?;
        println!("Club class table created");

        self.session
            .query_unpaged(
                "CREATE TABLE IF NOT EXISTS mma.user_permission \
                (user_id uuid, club_id uuid, class_id uuid, permission int, created_ts timestamp, \
                 PRIMARY KEY (user_id, club_id, class_id, permission))",
                &[],
            )
            .await?;
        println!("User permission table created");

        self.session
            .query_unpaged(
                "CREATE TABLE IF NOT EXISTS mma.waiver \
                (waiver_id uuid, title text, waiver text, created_ts timestamp, creator_user_id uuid, \
                 PRIMARY KEY (waiver_id))",
                &[],
            )
            .await?;
        println!("Waiver table created");

        self.session
            .query_unpaged(
                "CREATE TABLE IF NOT EXISTS mma.latest_waiver \
                (waiver_id uuid, style_id uuid, class_id uuid, club_id uuid, created_ts timestamp, \
                 PRIMARY KEY (style_id, class_id, club_id))",
                &[],
            )
            .await?;
        println!("Latest waiver table created");

        self.session
            .query_unpaged(
                "CREATE TABLE IF NOT EXISTS mma.signed_waiver \
                (waiver_id uuid, style_id uuid, class_id uuid, club_id uuid, user_id uuid, accepted_ts timestamp, \
                 PRIMARY KEY (user_id, waiver_id, style_id, class_id, club_id))",
                &[],
            )
            .await?;
        println!("signed_waiver table created");


        self.session
        .query_unpaged(
            "CREATE TABLE IF NOT EXISTS mma.class \
            (class_id uuid, venue_id uuid, waiver_id uuid, capacity int, publish_mode int, price decimal, notify_booking boolean, title text, description text, created_ts timestamp, end_ts timestamp, creator_user_id uuid, \
                PRIMARY KEY (class_id))",
            &[],
        )
        .await?;
        println!("Class table created");
        

        self.session
        .query_unpaged(
            "CREATE TABLE IF NOT EXISTS mma.class_styles \
            (class_id uuid, style_id uuid, \
                PRIMARY KEY (class_id, style_id))",
            &[],
        )
        .await?;
        println!("class_styles created");

        self.session
        .query_unpaged(
            "CREATE TABLE IF NOT EXISTS mma.class_grades \
            (class_id uuid, grade_id uuid, \
                PRIMARY KEY (class_id, grade_id))",
            &[],
        )
        .await?;
        println!("class_grades created");

        self.session
        .query_unpaged(
            "CREATE TABLE IF NOT EXISTS mma.class_frequency \
            (class_id uuid, class_frequency_id uuid, frequency int, start_date date, end_date date, start_time time, end_time time, \
                PRIMARY KEY (class_id, class_frequency_id))",
            &[],
        )
        .await?;
        println!("class_frequency created");

        self.session
        .query_unpaged(
            "CREATE TABLE IF NOT EXISTS mma.instructor \
            (user_id uuid, class_id uuid, permission int, created_ts timestamp, \
                PRIMARY KEY (user_id, class_id))",
            &[],
        )
        .await?;
        println!("Instructor table created");

        self.session
        .query_unpaged(
            "CREATE TABLE IF NOT EXISTS mma.attendance \
            (user_id uuid, class_id uuid, is_instructor boolean, checkin_ts timestamp, \
                PRIMARY KEY (user_id, class_id))",
            &[],
        )
        .await?;
        println!("Attendance table created");

        self.session
        .query_unpaged(
            "CREATE TABLE IF NOT EXISTS mma.style \
            (style_id uuid, title text, description text, \
                PRIMARY KEY (style_id))",
            &[],
        )
        .await?;
        println!("Style table created");

        self.session
        .query_unpaged(
            "CREATE TABLE IF NOT EXISTS mma.grade \
            (grading_id uuid, title text, description text, attendance_req int, rank int, \
                PRIMARY KEY (grading_id))",
            &[],
        )
        .await?;
        println!("Grade table created");


        self.session
        .query_unpaged(
            "CREATE TABLE IF NOT EXISTS mma.grading_requirement \
            (grading_requirement_id uuid, title text, description text, requirement int, \
                PRIMARY KEY (grading_requirement_id))",
            &[],
        )
        .await?;
        println!("Grading requirement table created");

        self.session
        .query_unpaged(
            "CREATE TABLE IF NOT EXISTS mma.user_style_grade \
            (style_id uuid, user_id uuid, grading_id uuid, note text, created_ts timestamp, \
                PRIMARY KEY (style_id, user_id, grading_id))",
            &[],
        )
        .await?;
        println!("User style grade table created");


        self.session
        .query_unpaged(
            "CREATE TABLE IF NOT EXISTS mma.session \
            (session_token text, user_id uuid, created_ts timestamp, expires_ts timestamp, \
             ip_address text, user_agent text, is_active boolean, \
             PRIMARY KEY (session_token, user_id))",
            &[],
        )
        .await?;
        println!("Session table created");

        self.session
        .query_unpaged(
            "CREATE TABLE IF NOT EXISTS mma.user_by_email \
            (email text PRIMARY KEY, user_id uuid, password_hash text,)",
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
            .query_unpaged(
                "SELECT user_id, password_hash FROM mma.user_by_email WHERE email = ?",
                (email,),
            )
            .await?
            .into_rows_result()?;

        for row in email_result.rows()?
        {
            let (user_id, password_hash): (Uuid, String) = row?;
            return Ok(Some((user_id, password_hash)));
        }

        return Ok(None);
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
                
        // Get current timestamp
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let expires = now + (duration_hours * 60*60 * 1000);

        let now = scylla::value::CqlTimestamp(now);
        let expires =scylla::value::CqlTimestamp(expires);


        println!("Session token: {}", session_token);
        // Store the session in the database
        self.session
            .query_unpaged(
                "INSERT INTO mma.session (session_token, user_id, created_ts, expires_ts, ip_address, user_agent, is_active) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    &session_token,
                    user_id,
                    now,
                    expires,
                    ip_address.unwrap_or_default(),
                    user_agent.unwrap_or_default(),
                    true,
                ),
            )
            .await?;
        
        Ok(session_token)
    }

    // Verify a session token and return the user ID if valid
    pub async fn verify_session(&self, user_id: Uuid, session_token: &str) -> Result<bool> {
        // println!("Verifying session: {}", session_token);
        let result = self.session
            .query_unpaged(
                "SELECT expires_ts, is_active FROM mma.session WHERE session_token = ? and user_id = ?",
                (session_token, user_id),
            )
            .await?
            .into_rows_result()?;

        for row in result.rows()?
        {
            let (expires_ts, is_active): (CqlTimestamp, bool, ) = row?;
            let now = Utc::now().timestamp();
            // Check if session is valid (not expired and is active)
            if now <= expires_ts.0 && is_active {
                return Ok(true);
            } else {
                // Optionally invalidate expired sessions
                if now > expires_ts.0 {
                    self.invalidate_session(user_id, session_token).await?;
                }
                return Ok(false);
            }
        }

        return Ok(false);

    }
    
    // Invalidate a session (logout)
    pub async fn invalidate_session(&self, user_id: Uuid, session_token: &str) -> Result<()> {
        self.session
            .query_unpaged(
                "UPDATE mma.session SET is_active = false WHERE session_token = ? and user_id = ?",
                (session_token, user_id),
            )
            .await?;
        
        Ok(())
    }
    
    // Invalidate all sessions for a user (force logout everywhere)
    pub async fn invalidate_all_user_sessions(&self, user_id: Uuid) -> Result<()> {
        self.session
            .query_unpaged(
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
        let result = self.session
            .query_unpaged(
                "SELECT user_id FROM mma.user_by_email WHERE email = ?",
                (email,),
            )
            .await?
            .into_rows_result()?;

        
        for row in result.rows()?
        {
            let (user_id,): (Uuid,) = row?;
            println!("User already exists ID: {}", user_id);
            return Err(AppError::Internal(format!("Email {} is already registered", email)));
        }

        // if let Ok(_) = email_check.first_row() {
        //     return Err(AppError::Internal(format!("Email {} is already registered", email)));
        // }
        
        // Hash the password
        let password_hash = hash_password(password)?;
        
        // Generate a new user ID
        let user_id = Uuid::new_v4();
        
        // Get current timestamp
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let now = scylla::value::CqlTimestamp(now);
        
        // Insert main user record
        self.session
            .query_unpaged(
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
            .query_unpaged(
                "INSERT INTO mma.user_by_email (email, user_id, password_hash) VALUES (?, ?, ?)",
                (email, user_id, &password_hash),
            )
            .await?;
        
        Ok(user_id)
    }



    



    // Get User Profile Data by ID ---
    pub async fn get_user_profile(&self, user_id: Uuid) -> Result<Option<UserProfileData>> {
        let result = self.session
            .query_unpaged(
                "SELECT user_id, email, first_name, surname, gender, phone, dob, \
                stripe_payment_method_id, email_verified, \
                photo_id, address, suburb, emergency_name, emergency_relationship, \
                emergency_phone, emergency_medical, belt_size, uniform_size, \
                member_number, contracted_until \
                FROM mma.user WHERE user_id = ?",
                (user_id,),
            )
            .await?
            .into_rows_result()?;
        
        for row in result.rows::<UserRow>()?
        {
            let row = row?;

            // Successfully retrieved a row. Now extract the columns.
            let user_profile = UserProfileData {
                user_id: row.user_id, // UserID is primary key
                email: row.email,
                first_name: row.first_name,
                surname: row.surname,
                gender: row.gender,
                phone: row.phone,
                dob: row.dob,
                stripe_payment_method_id: row.stripe_payment_method_id,
                email_verified: row.email_verified, 
                photo_id: row.photo_id,
                address: row.address,
                suburb: row.suburb,
                emergency_name: row.emergency_name,
                emergency_relationship: row.emergency_relationship,
                emergency_phone: row.emergency_phone,
                emergency_medical: row.emergency_medical,
                belt_size: row.belt_size,
                uniform_size: row.uniform_size,
                member_number: row.member_number,
                contracted_until: row.contracted_until.map(|naive_date: NaiveDate| {
                    naive_date.format("%Y-%m-%d").to_string() // "YYYY-MM-DD"
                }),
            };
            return Ok(Some(user_profile));
        }
                    
        return Ok(None); // User ID not found
    }

    // Update User Profile ---
    pub async fn update_user_profile(&self, user_id: Uuid, update_data: &UpdateUserProfileRequest) -> Result<()> {
        self.session
            .query_unpaged(
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
            .query_unpaged(
                "SELECT password_hash FROM mma.user WHERE user_id = ?",
                (user_id,),
            )
            .await?            
            .into_rows_result()?;

        for row in result.rows()?
        {
            let (password_hash,): (String,) = row?;
            return Ok(Some(password_hash));
        }
        return Ok(None);
    }

    // Update Password Hash by ID ---
    pub async fn update_password_hash(&self, user_id: Uuid, new_password_hash: String) -> Result<()> {
        self.session
            .query_unpaged(
                "UPDATE mma.user SET password_hash = ? WHERE user_id = ?",
                (&new_password_hash, user_id),
            )
            .await?;

        let result = self.session.query_unpaged("SELECT email from mma.user where user_id = ?", (user_id, ))
            .await?
            .into_rows_result()?;

        for row in result.rows()?
        {
            let (email,): (String,) = row?;
            self.session
                .query_unpaged(
                    "UPDATE mma.user_by_email SET password_hash = ? WHERE email = ?",
                    (&new_password_hash, email),
                )
                .await?;
        }

        Ok(())
    }

    pub async fn get_latest_waiver(&self, club_id: Option<Uuid>, class_id: Option<Uuid>, style_id: Option<Uuid>) -> AppResult<Option<(Uuid, String, String)>> {
        let zero_guuid = Uuid::nil();
        let _club_id = club_id.unwrap_or(zero_guuid);
        let _class_id = class_id.unwrap_or(zero_guuid);
        let _style_id = style_id.unwrap_or(zero_guuid);
        let result = self.session
            .query_unpaged(
                "SELECT waiver_id FROM mma.latest_waiver",
                ()
            )
            .await?            
            .into_rows_result()?;

        for row in result.rows()?
        {
            let (waiver_id,): (Uuid,) = row?;
            let waiver_tuple = self.get_waiver(waiver_id).await?;
            if waiver_tuple.is_none() {
                println!("No waiver found with ID: {}", waiver_id);
                return Ok(None);
            }

            let waiver_tuple = waiver_tuple.unwrap();
            return Ok(Some((waiver_id, waiver_tuple.0, waiver_tuple.1)));
        }
        return Ok(None);
    }


    pub async fn get_waiver(&self, waiver_id: Uuid) -> AppResult<Option<(String, String)>> {
        println!("Getting waiver with ID: {}", waiver_id);
        let result = self.session
            .query_unpaged(
                "SELECT title, waiver FROM mma.waiver WHERE waiver_id = ?",
                (waiver_id,),
            )
            .await?
            .into_rows_result()?;          
            
        if result.rows_num() == 0 {
            println!("No waiver found with ID: {}", waiver_id);
            return Ok(None);
        }
        
        for row in result.rows()?
        {
            let (title, waiver,): (String, String) = row?;
            return Ok(Some((title, waiver)));
        }
        return Ok(None);
    }
    
    
    pub async fn insert_user_accept_waiver_id(&self, user_id: Uuid, waiver_id: Uuid) -> AppResult<()> {

        let guuid_nil = Uuid::nil();
        self.session
            .query_unpaged(
                "INSERT INTO mma.signed_waiver (waiver_id, user_id, accepted_ts, style_id, class_id, club_id) \
                 VALUES (?, ?, ?, ?, ?, ?)",
                (
                    waiver_id,
                    user_id,
                    Utc::now().timestamp(),
                    guuid_nil,
                    guuid_nil,
                    guuid_nil
                ),
            )
            .await?;

        Ok(())
    }


    // Function to create a new waiver and make it current
    pub async fn create_new_waiver(&self, creator_user_id: Uuid, id: Uuid, title: String, content: String) -> AppResult<()> {
        // Get current timestamp
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let now = scylla::value::CqlTimestamp(now);

        self.session
            .query_unpaged(
                "INSERT INTO mma.waiver (waiver_id, title, waiver, creator_user_id, created_ts) VALUES (?, ?, ?, ?, ?)",
                (id, title, content, creator_user_id, now), // Include other fields as per your schema
            )
            .await?;

        let zero_guuid = Uuid::nil();
        self.session.query_unpaged("Insert into mma.latest_waiver (waiver_id, created_ts, club_id, class_id, style_id) VALUES (?, ?, ?, ?, ?)", 
            (id, now, zero_guuid, zero_guuid, zero_guuid)
        ).await?;


        Ok(())
    }

/* 
    // Function to create a new waiver and make it current
    pub async fn create_new_class(&self, creator_user_id: Uuid, class_id: Uuid, title: String, description: String, venue_id: Uuid, style_ids :&Vec<Uuid>, grading_ids :&Vec<Uuid>, price: BigDecimal, publish_mode: i32, capacity: i32, frequency: &Vec<ClassFrequency>, notify_booking: bool) -> AppResult<()> {
        // Get current timestamp
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        // let price: Option<CqlDecimal> = price
        //     .map(|p| CqlDecimal::from(p));

        let a = self.session
            .query_unpaged(
                "INSERT INTO mma.class (creator_user_id, class_id, title, description, created_ts, venue_id, publish_mode, capacity, notify_booking, price) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (creator_user_id, class_id, title, description, now, venue_id, publish_mode, capacity, notify_booking, price), 
            )
            .await;

        let zero_guuid = Uuid::nil();
 

        Ok(())
    }*/



}
