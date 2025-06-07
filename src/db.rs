use bigdecimal::num_bigint::BigInt;
// use argon2::password_hash;
use scylla::client::session::Session;
use scylla::client::session_builder::SessionBuilder;
use scylla::{DeserializeRow};
use scylla::statement::Statement;
use scylla::statement::prepared::PreparedStatement;
use scylla::statement::Consistency;
use std::fs;
use std::path::{Path, PathBuf};
use crate::db_migrate::MigrationTool;
use crate::payment_plan::{self, PaymentGroupType, PaymentPlanDuration};
use bigdecimal::ToPrimitive;

use std::sync::Arc;
use uuid::Uuid;
use std::time::SystemTime;
use rand::{distributions::Alphanumeric, Rng};
use chrono::{Datelike, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Utc, Weekday};
use chrono_tz::Tz;
use scylla::value::CqlTimestamp;
use bigdecimal::BigDecimal;
use crate::db;
use crate::error::{AppError, Result, Result as AppResult, TraceErr};
use crate::api::{UserProfileData, UpdateUserProfileRequest, ClassData, ClassFrequency, VenueData, StyleData, ClassFrequencyId, SchoolUserId, StudentClassAttendance}; 
use crate::stripe_client::StripeClient;

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
    dev_stripe_payment_method_ids: Option<Vec<String>>, // 8: text (nullable)
    prod_stripe_payment_method_ids: Option<Vec<String>>, // 8: text (nullable)
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


// Struct to represent a single class row fetched from the DB
#[derive(DeserializeRow)] // Add DeserializeRow and Serialize/Deserialize for API
pub struct ClassDataRow {
    pub class_id: Uuid,
    pub venue_id: Uuid,
    pub waiver_id: Option<Uuid>, // Assuming waiver_id can be null
    pub capacity: i32,
    pub publish_mode: i32,
    pub price: Option<BigDecimal>, // Assuming price can be null
    pub notify_booking: bool,
    pub title: String,
    pub description: String,
    pub styles: Vec<Uuid>,
    pub grades: Vec<Uuid>,
    pub deleted_ts: Option<CqlTimestamp>,
    pub free_lessons: Option<i32>,
}

pub fn get_time() -> i64
{
    SystemTime::now()
    .duration_since(SystemTime::UNIX_EPOCH)
    .unwrap_or_default()
    .as_millis() as i64
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
        .map_err(|e| AppError::Internal(format!("Invalid password hash format: {}", e))).trace()?;
    
    // Verify the password against the hash
    let result = Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok();
    // let result = true;
    Ok(result)
}



#[derive(Debug, Clone)]
pub struct ScyllaConnector {
    session: Arc<Session>,
    select_user_by_email_stmt: Arc<PreparedStatement>,
    dev_mode: bool,
}

pub async fn create_prepared_statement(session: &Session, query: &str) -> Result<Arc<PreparedStatement>> {
    let prepared_statement = session.prepare(query).await.trace()?;
    // prepared_statement.set_consistency(Consistency::LocalQuorum);
    Ok(Arc::new(prepared_statement))
}



pub async fn init_schema(session: &Session) -> Result<()> {
    println!("Building keyspace mma");
    // Create keyspace
    session
        .query_unpaged(
            "CREATE KEYSPACE IF NOT EXISTS mma WITH REPLICATION = \
            {'class': 'SimpleStrategy', 'replication_factor': 1}",
            &[],
        )
        .await.trace()?;
    println!("Keyspace created");
        
    // Set up tables if empty otherwise migrate tables if old schema
    let migration = MigrationTool::new("mma".to_string(), PathBuf::from("schema"));
    migration.migrate_to_version(session, 2).await.trace()?;

    println!("Schema initialized");
    Ok(())
}


impl ScyllaConnector {
    pub async fn new(nodes: &[&str], dev_mode: bool) -> Result<Self> {
        let session = SessionBuilder::new()
            .known_nodes(nodes)
            .user("cassandra", "cassandra")
            .build()
            .await
            .map_err(|e| AppError::Internal(format!("Failed to connect to Scylla: {}", e))).trace()?;
        println!("DB Connected");
        init_schema(&session).await.trace()?;
        let select_user_by_email_stmt = create_prepared_statement(&session, "SELECT logged_user_id, password_hash FROM mma.logged_user WHERE email = ?").await.trace()?;

        Ok(Self {
            session: Arc::new(session),
            select_user_by_email_stmt,
            dev_mode
        })
    }

    pub async fn get_logged_user_by_email(&self, email: &str) -> Result<Option<(Uuid, String)>> {
        // First, get the user_id from the email lookup table
        let email_result = self.session
            .execute_unpaged(
                // "SELECT user_id, password_hash FROM mma.user_by_email WHERE email = ?",
                &self.select_user_by_email_stmt.clone(),
                (email,),
            )
            .await?
            .into_rows_result().trace()?;
        // let email_result = self.session
        //     .query_unpaged(
        //         "SELECT logged_user_id, password_hash FROM mma.logged_user WHERE email = ?",
        //         (email,),
        //     )
        //     .await?
        //     .into_rows_result().trace()?;
        for row in email_result.rows()?
        {
            let (user_id, password_hash): (Uuid, String) = row.trace()?;
            return Ok(Some((user_id, password_hash)));
        }

        return Ok(None);
    }

    pub async fn create_session(
        &self,
        logged_user_id: &Uuid,
        ip_address: Option<String>,
        user_agent: Option<String>,
        duration_hours: i64
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


        // println!("Session token: {}", session_token);
        // Store the session in the database
        self.session
            .query_unpaged(
                "INSERT INTO mma.session (session_token, logged_user_id, created_ts, expires_ts, ip_address, user_agent, is_active) \
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    &session_token,
                    logged_user_id,
                    now,
                    expires,
                    ip_address.unwrap_or_default(),
                    user_agent.unwrap_or_default(),
                    true
                ),
            )
            .await.trace()?;
        
        Ok(session_token)
    }


    pub async fn get_logged_user_school_ids(&self, logged_user_id: &Uuid) -> Result<Vec<SchoolUserId>> {
        let result = self.session
            .query_unpaged(
                "SELECT school_user_ids FROM mma.logged_user WHERE logged_user_id = ?",
                (logged_user_id,),
            )
            .await?
            .into_rows_result().trace()?;
        
        let mut school_ids = Vec::new();
        for row in result.rows::<(Vec<(Uuid, Uuid)>,)>()? {
            let (schools,): (Vec<(Uuid, Uuid)>,) = row.trace()?;
            school_ids.extend(schools.into_iter().map(|(school_id, user_id)| SchoolUserId { school_id, user_id }));
        }
        return Ok(school_ids);
    }



    // Verify a session token and return the user ID if valid
    pub async fn verify_session(&self, logged_user_id: &Uuid, session_token: &str) -> Result<(bool, i64, Option::<Vec<SchoolUserId>>)> {
        // println!("Verifying session: {}", session_token);
        let result = self.session
            .query_unpaged(
                "SELECT expires_ts, is_active FROM mma.session WHERE session_token = ? and logged_user_id = ?",
                (session_token, logged_user_id),
            )
            .await?
            .into_rows_result().trace()?;

        

        for row in result.rows()?
        {
            let (expires_ts, is_active): (CqlTimestamp, bool) = row.trace()?;
            let now = Utc::now().timestamp();

            // Check if session is valid (not expired and is active)
            if now <= expires_ts.0 && is_active {
                // Fetch the school IDs associated with this logged user
                let school_ids = self.get_logged_user_school_ids(logged_user_id).await.trace()?;
                // println!("Session valid for logged_user_id: {}, expires at: {}", logged_user_id, expires_ts.0);

                return Ok((true, expires_ts.0, Some(school_ids))); // Session is valid
            } else {
                // Optionally invalidate expired sessions
                if now > expires_ts.0 {
                    self.invalidate_session(logged_user_id, session_token).await.trace()?;
                }
                return Ok((false, 0, None)); // Session expired or inactive
            }
        }

        return Ok((false, 0, None));

    }
    
    // Invalidate a session (logout)
    pub async fn invalidate_session(&self, user_id: &Uuid, session_token: &str) -> Result<()> {
        self.session
            .query_unpaged(
                "UPDATE mma.session SET is_active = false WHERE session_token = ? and logged_user_id = ?",
                (session_token, user_id),
            )
            .await.trace()?;
        
        Ok(())
    }
    
    // Invalidate all sessions for a user (force logout everywhere)
    pub async fn invalidate_all_user_sessions(&self, user_id: Uuid) -> Result<()> {
        self.session
            .query_unpaged(
                "UPDATE mma.session SET is_active = false WHERE logged_user_id = ?",
                (user_id,),
            )
            .await.trace()?;
        
        Ok(())
    }

    // Add user creation method
    pub async fn create_user(
        &self, 
        email: &str,
        password: Option<&str>,
        password_hash: Option<&str>,
        first_name: &str,
        surname: &str,
        email_verified: bool,
        school_id: &Option<Uuid>,
        _user_id: &Option<Uuid>
    ) -> Result<Uuid> {


        // if let Ok(_) = email_check.first_row() {
        //     return Err(AppError::Internal(format!("Email {} is already registered", email)));
        // }
        
        // Hash the password
        let password_hash = if let Some(p) = password {
            hash_password(p)? // Handle the potential error from hashing
        } else if let Some(ph) = password_hash {
            ph.to_string() // Convert &str to String to match the hash_password return type
        } else {
            return Err(AppError::Internal("Password or password hash is required".to_string()));
        };
        // let password_hash = hash_password(password).trace()?;
        
        // Generate a new user ID
        let user_id = if let Some(id) = _user_id {
            *id
        } else {
            Uuid::new_v4()
        };
        // let user_id = Uuid::new_v4();
        
        // Get current timestamp
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let now = scylla::value::CqlTimestamp(now);
        let school_id = match school_id {
            Some(school_id) => *school_id,
            None => Uuid::new_v4(), // Default to a new UUID if school_id is None
        };


        // Insert main user record
        match _user_id
            { Some(_user_id) => {
                self.session
                .query_unpaged(
                    "update mma.user (password_hash, email_verified, school_id) \
                     VALUES (?, ?, ?) where user_id = ?",
                    (
                        &password_hash,
                        email_verified,
                        school_id,
                        user_id,
                    ),
                )
                .await
                .trace_err("Updating db user")?;
            },
            None => {
                // Check if email already exists using the email lookup table
                let result = self.session
                    .query_unpaged(
                        "SELECT user_id FROM mma.user WHERE email = ?",
                        (email,),
                    )
                    .await?
                    .into_rows_result().trace()?;

                
                for row in result.rows()?
                {
                    let (user_id,): (Uuid,) = row.trace()?;
                    println!("User already exists ID: {}", user_id);
                    return Err(AppError::Internal(format!("Email {} is already registered", email)));
                }


                self.session
                .query_unpaged(
                    "INSERT INTO mma.user (user_id, email, first_name, surname, \
                     created_ts, email_verified, school_id) \
                     VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        user_id,
                        email,
                        first_name,
                        surname,
                        now,
                        email_verified,
                        school_id
                    ),
                )
                .await
                .trace_err("creating db user")?;


                let logged_user_id = Uuid::new_v4();
                let mut school_user_ids = Vec::new();
                school_user_ids.push((school_id, user_id));
                self.session
                .query_unpaged(
                    "INSERT INTO mma.logged_user (logged_user_id, email, password_hash, \
                     created_ts, email_verified, school_user_ids) \
                     VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        logged_user_id,
                        email,
                        &password_hash,
                        now,
                        email_verified,
                        &school_user_ids
                    ),
                )
                .await
                .trace_err("creating db logged_user")?;


                self.create_school(&user_id, &school_id, &None, &None).await.trace()?;
            }
        }

        


        
        
        // Insert into email lookup table
        // self.session
        //     .query_unpaged(
        //         "INSERT INTO mma.user_by_email (email, user_id, password_hash) VALUES (?, ?, ?)",
        //         (email, user_id, &password_hash),
        //     )
        //     .await.trace()?;
        
        Ok(user_id)
    }

    // Get User Profile Data by ID ---
    pub async fn get_user_profile(&self, user_id: Uuid) -> Result<Option<UserProfileData>> {
        let result = self.session
            .query_unpaged(
                "SELECT user_id, email, first_name, surname, gender, phone, dob, \
                dev_stripe_payment_method_ids, prod_stripe_payment_method_ids, email_verified, \
                photo_id, address, suburb, emergency_name, emergency_relationship, \
                emergency_phone, emergency_medical, belt_size, uniform_size, \
                member_number, contracted_until \
                FROM mma.user WHERE user_id = ?",
                (user_id,),
            )
            .await?
            .into_rows_result().trace()?;
        
        for row in result.rows::<UserRow>()?
        {
            let row = row.trace()?;
            let stripe_payment_method_id = if self.dev_mode {
                row.dev_stripe_payment_method_ids
            } else {
                row.prod_stripe_payment_method_ids
            };
            let stripe_payment_method_ids = match stripe_payment_method_id {
                Some(ids) => ids,
                None => Vec::new(), // Default to empty vector if None
            };

            // Check if the row is empty
            // Successfully retrieved a row. Now extract the columns.
            let user_profile = UserProfileData {
                user_id: row.user_id, // UserID is primary key
                email: row.email,
                first_name: row.first_name,
                surname: row.surname,
                gender: row.gender,
                phone: row.phone,
                dob: row.dob,
                stripe_payment_method_ids: stripe_payment_method_ids,
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
            .await.trace()?;
        Ok(())
    }

    // This is separate from get_user_profile for security
    pub async fn get_password_hash(&self, logged_user_id: Uuid) -> Result<Option<String>> {
        let result = self.session
            .query_unpaged(
                "SELECT password_hash FROM mma.logged_user WHERE logged_user_id = ?",
                (logged_user_id,),
            )
            .await?            
            .into_rows_result().trace()?;

        for row in result.rows()?
        {
            let (password_hash,): (String,) = row.trace()?;
            return Ok(Some(password_hash));
        }
        return Ok(None);
    }

    // Update Password Hash by ID ---
    pub async fn update_password_hash(&self, logged_user_id: Uuid, new_password_hash: String) -> Result<()> {
        self.session
            .query_unpaged(
                "UPDATE mma.logged_user SET password_hash = ? WHERE logged_user_id = ?",
                (&new_password_hash, logged_user_id),
            )
            .await.trace()?;

        Ok(())
    }

    pub async fn get_latest_waiver(&self, school_id: &Uuid, club_id: Option<Uuid>, class_id: Option<Uuid>, style_id: Option<Uuid>) -> AppResult<Option<(Uuid, String, String)>> {
        let zero_guuid = Uuid::nil();
        let _club_id = club_id.unwrap_or(zero_guuid);
        let _class_id = class_id.unwrap_or(zero_guuid);
        let _style_id = style_id.unwrap_or(zero_guuid);
        let result = self.session
            .query_unpaged(
                "SELECT waiver_id FROM mma.latest_waiver where school_id = ?",
                (school_id, )
            )
            .await?            
            .into_rows_result().trace()?;

        for row in result.rows()?
        {
            let (waiver_id,): (Uuid,) = row.trace()?;
            let waiver_tuple = self.get_waiver(&school_id, &waiver_id).await.trace()?;
            if waiver_tuple.is_none() {
                // println!("No waiver found with ID: {}", waiver_id);
                return Ok(None);
            }

            let waiver_tuple = waiver_tuple.unwrap();
            return Ok(Some((waiver_id, waiver_tuple.0, waiver_tuple.1)));
        }
        return Ok(None);
    }


    pub async fn get_waiver(&self, school_id: &Uuid, waiver_id: &Uuid) -> AppResult<Option<(String, String)>> {
        // println!("Getting waiver with ID: {}", waiver_id);
        let result = self.session
            .query_unpaged(
                "SELECT title, waiver FROM mma.waiver WHERE waiver_id = ? and school_id = ?",
                (waiver_id, school_id),
            )
            .await?
            .into_rows_result().trace()?;          
            
        if result.rows_num() == 0 {
            // println!("No waiver found with ID: {}", waiver_id);
            return Ok(None);
        }
        
        for row in result.rows()?
        {
            let (title, waiver,): (String, String) = row.trace()?;
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
            .await.trace()?;

        Ok(())
    }


    // Function to create a new waiver and make it current
    pub async fn create_new_waiver(&self, school_id: &Uuid, creator_user_id: &Uuid, id: &Uuid, title: &String, content: &String) -> AppResult<()> {
        // Get current timestamp
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let now = scylla::value::CqlTimestamp(now);

        self.session
            .query_unpaged(
                "INSERT INTO mma.waiver (school_id, waiver_id, title, waiver, creator_user_id, created_ts) VALUES (?, ?, ?, ?, ?, ?)",
                (school_id, id, title, content, creator_user_id, now), // Include other fields as per your schema
            )
            .await.trace()?;

        let zero_guuid = Uuid::nil();
        self.session.query_unpaged("Insert into mma.latest_waiver (school_id, waiver_id, created_ts, club_id, class_id, style_id) VALUES (?, ?, ?, ?, ?, ?)", 
            (school_id, id, now, zero_guuid, zero_guuid, zero_guuid)
        ).await.trace()?;


        Ok(())
    }


    // Function to create a new waiver and make it current
    pub async fn create_new_class(&self, school_id: &Uuid, creator_user_id: &Uuid, class_id: &Uuid, title: &String, description: &String, venue_id: &Uuid, style_ids :&Vec<Uuid>, grading_ids :&Vec<Uuid>, price: Option<BigDecimal>, publish_mode: i32, capacity: i32, class_frequency: &Vec<ClassFrequency>, notify_booking: bool, waiver_id: Option<Uuid>) -> AppResult<()> {
        // Get current timestamp
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let now = scylla::value::CqlTimestamp(now);
        // let price: Option<CqlDecimal> = price
        //     .map(|p| CqlDecimal::from(p));
        let zero_ts = scylla::value::CqlTimestamp(0);
        self.session
            .query_unpaged(
                "INSERT INTO mma.class (school_id, creator_user_id, class_id, title, description, created_ts, venue_id, publish_mode, capacity, notify_booking, price, waiver_id, styles, grades, deleted_ts, timezone) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (school_id, creator_user_id, class_id, title, description, now, venue_id, publish_mode, capacity, notify_booking, price, waiver_id, style_ids, grading_ids, zero_ts, "Australia/Sydney"), 
            )
            .await.trace()?;

        for style_id in style_ids {
            self.session
                .query_unpaged(
                    "INSERT INTO mma.class_styles (class_id, style_id) VALUES (?, ?)",
                    (class_id, *style_id), 
                )
                .await.trace()?;
        }

        for grade_id in grading_ids {
            self.session
                .query_unpaged(
                    "INSERT INTO mma.class_grades (class_id, grade_id) VALUES (?, ?)",
                    (class_id, *grade_id), 
                )
                .await.trace()?;
        }

        for frequency in class_frequency {
            let class_frequency_id = Uuid::new_v4();


            self.session
                .query_unpaged(
                    "INSERT INTO mma.class_frequency (class_id, class_frequency_id, frequency, start_date, end_date, start_time, end_time) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (class_id, class_frequency_id, frequency.frequency, &frequency.start_date, &frequency.end_date, &frequency.start_time, &frequency.end_time), 
                )
                .await.trace()?;
        }

        Ok(())
    }


    // Function to create a new waiver and make it current
    pub async fn update_class(&self, school_id: &Uuid, _creator_user_id: &Uuid, class_id: &Uuid, title: &String, description: &String, venue_id: &Uuid, style_ids :&Vec<Uuid>, grading_ids :&Vec<Uuid>, price: Option<BigDecimal>, publish_mode: i32, capacity: i32, class_frequency: &Vec<ClassFrequencyId>, notify_booking: bool, waiver_id: Option<Uuid>, free_lessons: Option<i32>) -> AppResult<()> {
        
        match waiver_id {
            Some(waiver_id) => {
                // Check if the waiver exists
                let waiver_exists = self.get_waiver(school_id, &waiver_id).await.trace()?;
                if waiver_exists.is_none() {
                    return Err(AppError::Internal(format!("Waiver with ID {} does not exist", waiver_id)));
                }
            },
            None => {
                // If no waiver is provided, we can skip this check
            }
        }
        
        self.session
            .query_unpaged(
                "INSERT INTO mma.class (school_id, class_id, title, description, venue_id, publish_mode, capacity, notify_booking, price, waiver_id, styles, grades, free_lessons) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (school_id, class_id, title, description, venue_id, publish_mode, capacity, notify_booking, price, waiver_id, style_ids, grading_ids, free_lessons), 
            )
            .await.trace()?;

        for style_id in style_ids {
            self.session
                .query_unpaged(
                    "INSERT INTO mma.class_styles (class_id, style_id) VALUES (?, ?)",
                    (class_id, *style_id), 
                )
                .await.trace()?;
        }

        for grade_id in grading_ids {
            self.session
                .query_unpaged(
                    "INSERT INTO mma.class_grades (class_id, grade_id) VALUES (?, ?)",
                    (class_id, *grade_id), 
                )
                .await.trace()?;
        }


        let result = self.session
            .query_unpaged(
                "SELECT class_frequency_id FROM mma.class_frequency WHERE class_id = ?",
                (class_id,),
            )
            .await?
            .into_rows_result().trace()?;

        let mut delete_class_frequency_ids: Vec<Uuid> = Vec::new();
        for row in result.rows()?
        {
            let ( class_frequency_id, ) : ( Uuid, ) = row.trace()?;
            delete_class_frequency_ids.push(class_frequency_id);
        }

        for frequency in class_frequency {
            let class_frequency_id = frequency.class_frequency_id;
            delete_class_frequency_ids.retain(|&x| x != class_frequency_id);
        }

        if delete_class_frequency_ids.len() > 0 {
            self.session
                .query_unpaged(
                    "DELETE FROM mma.class_frequency WHERE class_id = ? and class_frequency_id in ?",
                    (class_id, delete_class_frequency_ids), 
                )
                .await.trace()?;
        }
        
        for frequency in class_frequency {
            let class_frequency_id = frequency.class_frequency_id;

            self.session
                .query_unpaged(
                    "INSERT INTO mma.class_frequency (class_id, class_frequency_id, frequency, start_date, end_date, start_time, end_time) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (class_id, class_frequency_id, frequency.frequency, &frequency.start_date, &frequency.end_date, &frequency.start_time, &frequency.end_time), 
                )
                .await.trace()?;
        }

        Ok(())
    }


    // Function to get all classes with optional filtering
    // Returns Ok(Vec<ClassData>) - an empty vector if no classes match filters or no classes exist
    pub async fn get_classes(
        &self,
        school_id: &Uuid,
        _only_future: bool,
        publish_mode_filter: Option<i32>,
    ) -> AppResult<Vec<ClassData>> {

        let result = self.session
            .query_unpaged("SELECT class_id, venue_id, waiver_id, capacity, publish_mode, price, notify_booking, title, description, styles, grades, deleted_ts, free_lessons FROM mma.class where school_id = ?", (school_id, )) // Pass the query string and bound values
            .await?
            .into_rows_result().trace()?;

        let mut classes: Vec<ClassData> = Vec::new();
        for row in result.rows::<ClassDataRow>()?
        {
            let row = row.trace()?;
            // Successfully retrieved a row. Now extract the columns.
            if publish_mode_filter.is_none() || publish_mode_filter == Some(row.publish_mode) {

                let class_data = ClassData {
                    class_id: row.class_id,
                    venue_id: row.venue_id,
                    waiver_id: row.waiver_id,
                    capacity: row.capacity,
                    publish_mode: row.publish_mode,
                    price: row.price,
                    notify_booking: row.notify_booking,
                    title: row.title,
                    description: row.description,
                    frequency: Vec::new(), // Initialize with an empty vector
                    styles: row.styles, // Initialize with an empty vector
                    grades: row.grades,
                    free_lessons: row.free_lessons,
                };
                classes.push(class_data);
            } 
        }

        for class in &mut classes {
            let class_id = class.class_id;

            let result = self.session
            .query_unpaged(
                "SELECT class_frequency_id, frequency, start_date, end_date, start_time, end_time FROM mma.class_frequency WHERE class_id = ?",
                (class_id,),
            )
            .await?
            .into_rows_result().trace()?;

            for row in result.rows()?
            {
                let ( class_frequency_id, frequency, start_date, end_date, start_time, end_time) : ( Uuid, i32, NaiveDate, NaiveDate, NaiveTime, NaiveTime) = row.trace()?;
                let class_frequency = ClassFrequencyId {
                    class_frequency_id: class_frequency_id,
                    frequency: frequency,
                    start_date: start_date,
                    end_date: end_date,
                    start_time: start_time,
                    end_time: end_time,
                };
                class.frequency.push(class_frequency);
            }
        }

        return Ok(classes);
    }


    pub async fn add_stripe_customer_id(
        &self,
        user_id: &Uuid,
        stripe_customer_id: &String,
    ) -> AppResult<()> {
        let stripe_customer_str = match self.dev_mode {
            true => "dev_stripe_customer_id", // Use a dummy ID in dev mode
            false => "prod_stripe_customer_id",
        };

        self.session
            .query_unpaged(
                format!("UPDATE mma.user SET {} = ? WHERE user_id = ?", stripe_customer_str).as_str(),
                (stripe_customer_id, user_id),
            )
            .await.trace()?;
        Ok(())
    }

    // pub async fn add_stripe_payment_method_id(
    //     &self,
    //     user_id: &Uuid,
    //     stripe_payment_method_id: &String,
    // ) -> AppResult<()> {
    //     let stripe_payment_method_str = match self.dev_mode {
    //         true => "dev_stripe_payment_method_ids", // Use a dummy ID in dev mode
    //         false => "prod_stripe_payment_method_ids",
    //     };
    //     println!("Adding Stripe payment method ID: {} for user {}", stripe_payment_method_id, user_id);
    //     self.session
    //         .query_unpaged(
    //             format!("UPDATE mma.user SET {} = {} + ? WHERE user_id = ?", stripe_payment_method_str, stripe_payment_method_str).as_str(),
    //             (stripe_payment_method_id, user_id),
    //         )
    //         .await.trace()?;
    //     Ok(())
    // }

    pub async fn set_stripe_payment_method_ids(
        &self,
        user_id: &Uuid,
        stripe_payment_method_ids: &Vec<String>,
    ) -> AppResult<()> {
        let stripe_payment_method_str = match self.dev_mode {
            true => "dev_stripe_payment_method_ids", // Use a dummy ID in dev mode
            false => "prod_stripe_payment_method_ids",
        };
        self.session
            .query_unpaged(
                format!("UPDATE mma.user SET {} = ? WHERE user_id = ?", stripe_payment_method_str).as_str(),
                (stripe_payment_method_ids, user_id),
            )
            .await.trace()?;
        Ok(())
    }

    pub async fn remove_stripe_payment_method_id(
        &self,
        user_id: &Uuid,
        stripe_payment_method_id: &String,
    ) -> AppResult<()> {
        let stripe_payment_method_str = match self.dev_mode {
            true => "dev_stripe_payment_method_ids", // Use a dummy ID in dev mode
            false => "prod_stripe_payment_method_ids",
        };
        let mut stripe_payment_method_ids: Vec<String> = Vec::new();
        stripe_payment_method_ids.push(stripe_payment_method_id.to_string());
        self.session
            .query_unpaged(
                format!("UPDATE mma.user SET {} = {} - ? WHERE user_id = ?", stripe_payment_method_str, stripe_payment_method_str).as_str(),
                (&stripe_payment_method_ids, user_id),
            )
            .await.trace()?;
        Ok(())
    }


    pub async fn get_stripe_customer_id(
        &self,
        user_id: &Uuid,
    ) -> AppResult<Option<String>> {
        let stripe_customer_str = match self.dev_mode {
            true => "dev_stripe_customer_id", // Use a dummy ID in dev mode
            false => "prod_stripe_customer_id",
        };
        let result = self.session
            .query_unpaged(
                format!("SELECT {} FROM mma.user WHERE user_id = ?", stripe_customer_str).as_str(),
                (user_id,),
            )
            .await?
            .into_rows_result().trace()?;

        for row in result.rows()? {
            let (stripe_customer_id,): (Option<String>,) = row.trace()?;
            return Ok(stripe_customer_id);
        }
        return Ok(None);
    }

    pub async fn get_stripe_payment_method_id(
        &self,
        user_id: &Uuid,
    ) -> AppResult<Option<String>> {
        let stripe_customer_str = match self.dev_mode {
            true => "dev_stripe_payment_method_id", // Use a dummy ID in dev mode
            false => "prod_stripe_payment_method_id",
        };

        let result = self.session
            .query_unpaged(
                format!("SELECT {} FROM mma.user WHERE user_id = ?", stripe_customer_str).as_str(),
                (user_id, ),
            )
            .await?
            .into_rows_result().trace()?;

        for row in result.rows()? {
            let (stripe_customer_id,): (Option<String>,) = row.trace()?;
            return Ok(stripe_customer_id);
        }
        return Ok(None);
    }


    pub async fn get_venue(&self, venue_id: &Uuid, school_id: &Uuid) -> AppResult<Option<VenueData>> {
        let result = self.session
            .query_unpaged(
                "SELECT venue_id, title, description, address, suburb, postcode, state, country, latitude, longitude, contact_phone FROM mma.venue WHERE venue_id = ? and school_id = ?",
                (venue_id, school_id),
            )
            .await?
            .into_rows_result().trace()?;

        for row in result.rows::<VenueData, >()?
        {
            // let (title, description): (String, String) = row.trace()?;
            let row = row.trace()?;
            // Successfully retrieved a row. Now extract the columns.

            return Ok(Some(row));
        }
        return Ok(None); // Venue_id not found
    }


    pub async fn has_user_accepted_waiver(
        &self,
        user_id: &Uuid,
        waiver_id: &Uuid,
    ) -> AppResult<bool> {
        let result = self.session
            .query_unpaged(
                "SELECT user_id FROM mma.signed_waiver WHERE user_id = ? AND waiver_id = ?",
                (user_id, waiver_id),
            )
            .await?
            .into_rows_result().trace()?;

        if result.rows_num() > 0 {
            return Ok(true); // User has accepted the waiver
        }
        Ok(false) // User has not accepted the waiver
    }


    pub async fn get_user_class_attendance_count(
        &self,
        user_id: &Uuid,
        class_id: &Uuid,
    ) -> AppResult<i32> {
        let result = self.session
            .query_unpaged(
                "SELECT count FROM mma.attendance_count WHERE user_id = ? AND class_id = ?",
                (user_id, class_id),
            )
            .await?
            .into_rows_result()
            .trace_err("Getting db attending_count")?;

        for row in result.rows::<(i32,)>()? {
            let (count,) = row.trace()?;
            return Ok(count);
        }
        Ok(0) // No attendance found
    }

    pub async fn can_user_pay(
        &self,
        user_id: &Uuid,
    ) -> AppResult<bool> {
        let stripe_payment_method_str = match self.dev_mode {
            true => "dev_stripe_payment_method_ids", // Use a dummy ID in dev mode
            false => "prod_stripe_payment_method_ids",
        };

        let result = self.session
            .query_unpaged(
                format!("SELECT COUNT({}) FROM mma.user WHERE user_id = ? ", stripe_payment_method_str),
                (user_id, ),
            )
            .await?
            .into_rows_result()
            .trace_err("Checking for users payment methods")?;

        if result.rows_num() > 0 {
            for row in result.rows::<(i64,)>()? {
                let (count,) = row.trace()?;
                if count > 0 {
                    return Ok(true); // User has a payment method
                }
            }
        }
      
        Ok(false) // User has not paid for the class
    }



    pub async fn pay_class (
        &self,
        user_id: &Uuid,
        school_id: &Uuid,
        class_id: &Uuid,
        class_start_ts: i64,
        stripe_client: &StripeClient,
        free_lessons: i32,
        price: &Option<BigDecimal>
    ) -> AppResult<bool>
    {

        match price {
            Some(price) => {
                // Class is Free
                if *price == BigDecimal::from(0) { 
                    return Ok(true);
                }
                
                let stripe_payment_method_str = match self.dev_mode {
                    true => "dev_stripe_payment_method_ids", // Use a dummy ID in dev mode
                    false => "prod_stripe_payment_method_ids",
                };

                let stripe_customer_str = match self.dev_mode {
                    true => "dev_stripe_customer_id", // Use a dummy ID in dev mode
                    false => "prod_stripe_customer_id",
                };

                let result = self.session
                    .query_unpaged(format!("SELECT school_id, active_payment_plans, payment_provider, {}, {} FROM mma.user where user_id = ?", stripe_payment_method_str, stripe_customer_str), 
                    (user_id, )) // Pass the query string and bound values
                    .await.trace()?
                    .into_rows_result()
                    .trace_err("getting db user payment data")?;
                
                if result.rows_num() == 0 {
                    return Err(AppError::Internal(format!("User with ID {} does not exist", class_id)));
                }

                for row in result.rows().trace()? {
                    let mut expired_active_plans = Vec::new();

                    let (ref_school_id, active_payment_plans, payment_provider, stripe_payment_method_ids, stripe_customer_id): (Uuid, Option<Vec<(Uuid, CqlTimestamp)>>, Option<Uuid>, Option<Vec<String>>, Option<String>) = row.trace()?;
                    if ref_school_id != *school_id {
                        return Err(AppError::Internal(format!("User Id {} has wrong school ID {} class id {} does not exist", user_id, school_id, class_id)));
                    }

                    let now = get_time();
                    let mut has_pass = false;
                    // Check if active pass, also clean up expired passes
                    match active_payment_plans {
                        Some(active_payment_plans) => {
                            for active_payment_plan in active_payment_plans {
                                let (payment_plan_id, expiration_ts) = active_payment_plan;
                                let expiration_ts = expiration_ts.0;
                                if now > expiration_ts {
                                    expired_active_plans.push(active_payment_plan);
                                } else {
                                    has_pass = true;
                                } 
                            }
                        },
                        None => {}
                    }



                    // Clean up expired active plans
                    for explired_plan in expired_active_plans {
                        tracing::info!("expiring active_payment_plan");

                        let result = self.session
                            .query_unpaged("update mma.user set active_payment_plans = active_payment_plans - ? where user_id = ?", 
                            (explired_plan, user_id)) // Pass the query string and bound values
                            .await.trace()?
                            .into_rows_result().trace()?;
                    }

                    if has_pass {
                        return Ok(true);
                    }
                    
                    
                    // Try individuals payment methods first
                    match stripe_customer_id {
                        Some(stripe_customer_id) => {
                            match stripe_payment_method_ids {
                                Some(stripe_payment_method_ids) => {
                                    for payment_method_id in stripe_payment_method_ids {
                                        let transaction_id = Uuid::new_v4();
                                        let description = format!("Casual attendance of class:{}", class_id);
                                        let currency = "aud";
                                        // let amount = price*BigDecimal::from(100);
                                        let cents_i64 = (price * BigDecimal::from(100))
                                            .round(0)
                                            .to_i64()
                                            .unwrap();
                                        let result = stripe_client.charge_payment_method(cents_i64, currency, &payment_method_id, &stripe_customer_id, &transaction_id, school_id, user_id, Some(&description)).await.trace()?;
                                        // result.id
                                        let stripe_payment_id = result.id;
                                        let duration = PaymentPlanDuration::SingleClass as i32;
                                        let payment_status = 1; // captured

                                        let zero_guuid = Uuid::nil();
                                        let now = scylla::value::CqlTimestamp(now);
                                        let class_start_ts = scylla::value::CqlTimestamp(class_start_ts);
                                        
                                        let result = self.session
                                            .query_unpaged("insert into mma.user_payment (user_id, base_payment_plan_id, class_id, class_start_ts, created_ts, stripe_payment_id, captured_ts, captured, status) values (?, ?, ?, ?, ?, ?, ?, ?, ?)", 
                                            (user_id, zero_guuid, class_id, class_start_ts, now, stripe_payment_id, now, price, payment_status)) // Pass the query string and bound values
                                            .await.trace()?;
                                        return Ok(true);
                                        // CREATE TABLE IF NOT EXISTS {}.user_payment (user_payment_id uuid, user_id uuid, class_id uuid, class_start_ts timestamp, base_payment_plan_id uuid, payment_plan_id uuid, status int, stripe_payment_id text, created_ts timestamp, paid decimal, amount decimal, refunded decimal, refunded_ts timestamp, paid_ts timestamp, processing_ts timestamp, processing_node text, captured_ts timestamp, captured decimal, PRIMARY KEY (user_id, base_payment_plan_id, class_id, class_start_ts));

                                    }
                                }, 
                                None => {}
                            }
                        }, 
                        None => {}
                    }

                }
                
            },
            None => {return Ok(true); }
        }

        // Check if user has paid for the class
        let classes_attended = self.get_user_class_attendance_count(user_id, class_id).await.trace()?;
        if free_lessons <= classes_attended {
            let user_can_pay = self.can_user_pay(user_id).await.trace()?;
            if !user_can_pay {
                return Err(AppError::UserNoCreditCard("".to_string()));
            }
        }

        Ok(false)
    }


    pub async fn set_class_attendance (
        &self,
        class_id: &Uuid,
        school_id: &Uuid,
        user_ids: &Vec<Uuid>,
        present: &Vec<bool>,
        class_start_ts: i64,
        stripe_client: &StripeClient
    ) -> AppResult<bool> {

        let adding_student_count = present.iter().filter(|&&p| p).count();
        let remove_student_count = present.iter().filter(|&&p| !p).count();
        let total_student_attend_dif = adding_student_count as i32 - remove_student_count as i32;

        // SetClassStudentsAttendanceRequest
        let class_valid_ts = self.is_valid_class_start(&class_id, &school_id, class_start_ts, Some(total_student_attend_dif)).await.trace()?;
            // .map_err(|app_err| AppError::Internal(app_err.to_string()) ).trace()?; // Convert potential AppError from validate
        
        if !class_valid_ts {
            return Err(AppError::Internal("Invalid class start timestamp".to_string()));
        }

        let result = self.session
            .query_unpaged("SELECT waiver_id, price, free_lessons FROM mma.class where class_id = ? and school_id = ?", 
            (class_id, school_id)) // Pass the query string and bound values
            .await?
            .into_rows_result().trace()?;
        
        if result.rows_num() == 0 {
            return Err(AppError::Internal(format!("Class with ID {} does not exist", class_id)));
        }

        for row in result.rows()? {
            let (waiver_id, price, free_lessons): (Option<Uuid>, Option<BigDecimal>, Option<i32>) = row.trace()?;
            match waiver_id {
                Some(id) => {
                    for (user, present) in user_ids.iter().zip(present.iter()) {
                        if *present {
                            // Check if user has accepted the waiver
                            let accepted = self.has_user_accepted_waiver(user, &id).await.trace()?;
                            if !accepted {
                                return Err(AppError::UserWaiverNotAccepted(format!("")));
                            }
                        }
                    }
                },
                None => {}
            }

            if price.is_some() {
                let free_lessons = free_lessons.unwrap_or(0);
                // If the class has a price
                for (user, present) in user_ids.iter().zip(present.iter()) {
                    if *present {
                        let paid = self.pay_class(user, school_id, class_id, class_start_ts, stripe_client, free_lessons, &price).await.trace()?;
                        
                        if !paid { 
                            return Ok(false);
                        }

                    }
                }
            }

        }


        let class_start_ts: CqlTimestamp = scylla::value::CqlTimestamp(class_start_ts);

        // Get current timestamp
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let now = scylla::value::CqlTimestamp(now);

        // Prepare the statement once
        let prepared = self
            .session
            .prepare(
                "INSERT INTO mma.attendance (class_id, user_id, class_start_ts, is_instructor, checkin_ts) VALUES (?, ?, ?, ?, ?)"
            )
            .await.trace()?;

        let prepared_count = self
            .session
            .prepare(
                "INSERT INTO mma.attendance_count (class_id, user_id, count) VALUES (?, ?, ?)"
            )
            .await.trace()?;


        // Create batch
        let mut batch = scylla::statement::batch::Batch::default();
        // Add each user_id as a separate statement in the batch if present
        for (user_id, is_present) in user_ids.iter().zip(present.iter()) {
            if *is_present {
                batch.append_statement(prepared.clone());
            }
        }

        let batch_values: Vec<_> = user_ids
            .iter()
            .zip(present.iter())
            .filter_map(|(user_id, is_present)| {
                if *is_present {
                    Some((class_id, user_id, class_start_ts, false, now))
                } else {
                    None // Skip users not present
                }
            })
            .collect();

        // Execute batch
        self.session.batch(&batch, batch_values).await.trace()?;


        // Now remove attendance for users not present
        let not_present_user_ids: Vec<Uuid> = user_ids.iter()
            .zip(present.iter())
            .filter_map(|(user_id, is_present)| {
                if !is_present {
                    Some(user_id)
                } else {
                    None // Skip users who are present
                }
            })
            .cloned()
            .collect();

        if !not_present_user_ids.is_empty() {
            self.session
                .query_unpaged(
                    "DELETE FROM mma.attendance WHERE class_id = ? AND class_start_ts = ? and user_id IN ?",
                    (class_id, class_start_ts, not_present_user_ids),
                )
                .await.trace()?;
        }

        let mut batch = scylla::statement::batch::Batch::default();
        let mut batch_values: Vec<_> = Vec::new();
        // let classes_attended = self.get_user_class_attendance_count(user, class_id).await.trace()?;
        for (user_id, is_present) in user_ids.iter().zip(present.iter()) {
            if *is_present {
                batch.append_statement(prepared_count.clone());
                let attendance_count = self.get_user_class_attendance_count(user_id, class_id).await.trace()?;
                batch_values.push((class_id, user_id, attendance_count)); // Increment count by 1 for each present user
            }
        }

        // Execute batch for attendance count
        self.session.batch(&batch, batch_values).await.trace()?;



        // println!("Attendance set for class {}: {:?}", class_id, user_ids);
        Ok(true)
    }


    pub async fn is_valid_class_start (
        &self,
        class_id: &Uuid,
        school_id: &Uuid,
        query_class_start_ts: i64,
        student_attend_dif: Option<i32>,
    ) -> AppResult<bool> {
        let query_class_start_ts_cql: CqlTimestamp = scylla::value::CqlTimestamp(query_class_start_ts);
        
        // Convert timestamp to NaiveDateTime for comparison
        let query_class_datetime = NaiveDateTime::from_timestamp_millis(query_class_start_ts)
            .ok_or_else(|| AppError::Internal("Invalid timestamp".to_string())).trace()?;

        // Get current timestamp
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let now_cql = scylla::value::CqlTimestamp(now);
        

        let result = self.session
            .query_unpaged(
                "SELECT deleted_ts, school_id, timezone, capacity FROM mma.class WHERE class_id = ?",
                (class_id,),
            )
            .await?
            .into_rows_result().trace()?;   

        // Check if the class exists and is not deleted
        if result.rows_num() == 0 {
            println!("Class with ID {} does not exist", class_id);
            return Ok(false);
        }
        let mut timezone = String::new();
        for row in result.rows()? {
            let (deleted_ts, class_school_id, db_timezone, capacity): (CqlTimestamp, Uuid, String, Option<i32>) = row.trace()?;
            
            // Check if the class is deleted
            if deleted_ts != CqlTimestamp(0) {
                println!("Class with ID {} is deleted", class_id);
                return Ok(false);
            }
            
            // Check if the class belongs to the correct school
            if class_school_id != *school_id {
                println!("Class with ID {} does not belong to school {}", class_id, school_id);
                return Ok(false);
            }
            
            timezone = db_timezone;
            match capacity {
                Some(capacity) => {

                    match student_attend_dif {
                        Some(dif) => {
                            if dif > 0 {
                                let result = self.session
                                    .query_unpaged(
                                        "SELECT count(user_id) FROM mma.attendance WHERE class_id = ? and class_start_ts = ?",
                                        (class_id, query_class_start_ts_cql),
                                    )
                                    .await?
                                    .into_rows_result().trace()?;


                                let mut student_attend_count: i64 = 0;
                                for row in result.rows()? {
                                    let (count,): (i64,) = row.trace()?;
                                    student_attend_count = count;
                                }

                                if student_attend_count as i32 + dif > capacity as i32 {
                                    println!("Class with ID {} has insufficient capacity for the requested attendance change", class_id);
                                    return Err(AppError::ClassIsFull(format!("")));
                                    // return Ok(false);
                                }
                            }
                        },
                        None => {}
                    }
                },
                None => {}
            }

        }


        // Check if the class exists
        let result = self.session
            .query_unpaged(
                "SELECT class_frequency_id, frequency, start_date, end_date, start_time, end_time FROM mma.class_frequency WHERE class_id = ?",
                (class_id,),
            )
            .await?
            .into_rows_result().trace()?;
            
        if result.rows_num() == 0 {
            println!("Class with ID {} does not exist", class_id);
            return Ok(false);
        }
        
        // Check if the class is valid based on frequency rules
        for row in result.rows()? {
            let (class_frequency_id, frequency, start_date, end_date, start_time, end_time): 
                (Uuid, i32, NaiveDate, Option<NaiveDate>, NaiveTime, NaiveTime) = row.trace()?;
            
            let db_class_start_datetime = start_date.and_time(start_time);
            // Parse the timezone string into a Tz object
            let timezone = match timezone.parse::<Tz>() {
                Ok(tz) => tz,
                Err(_) => {
                    println!("Invalid timezone string: {}, defaulting to Australia/Sydney", timezone);
                    Tz::Australia__Sydney // Default to Australia/Sydney if parsing fails
                }
            };

            // Convert the naive datetime from DB to timezone-aware datetime, then to UTC timestamp
            let db_class_start_datetime_tz = timezone.from_local_datetime(&db_class_start_datetime)
                .single()
                .ok_or_else(|| AppError::Internal("Invalid datetime conversion".to_string())).trace()?;

            let db_class_start_datetime_utc_ts = db_class_start_datetime_tz.timestamp_millis();

            let query_class_start_datetime_tz = timezone.from_utc_datetime(&query_class_datetime);

            // println!("class_start_datetime local: {}", db_class_start_datetime);
            // println!("class_start_datetime timezone-aware: {}", db_class_start_datetime_tz);
            // println!("class_start_datetime UTC timestamp: {}", db_class_start_datetime_utc_ts);
            // println!("query_class_start_ts UTC timestamp: {} {} {}", query_class_start_ts, query_class_datetime, query_class_start_datetime_tz);

            // Check date bounds if end_date exists
            if let Some(end_date) = end_date {
                let db_class_end_datetime = end_date.and_time(end_time);
                // Convert the naive datetime from DB to timezone-aware datetime, then to UTC timestamp
                let db_class_end_datetime_tz = timezone.from_local_datetime(&db_class_end_datetime)
                    .single()
                    .ok_or_else(|| AppError::Internal("Invalid datetime conversion".to_string())).trace()?;

                let db_class_end_datetime_utc_ts = db_class_end_datetime_tz.timestamp_millis();
                
                if query_class_start_ts < db_class_start_datetime_utc_ts || query_class_start_ts > db_class_end_datetime_utc_ts {
                    continue; // This frequency rule doesn't apply to this timestamp
                }
            } else {
                // No end date bounds check, but still check if after start date
                if query_class_start_ts < db_class_start_datetime_utc_ts {
                    continue;
                }
            }
            
            // Check time bounds (must be within start_time and end_time on the day)
            // let class_time = class_datetime.time();

            let db_class_start_time = db_class_start_datetime_tz.time();
            let query_class_start_time = query_class_start_datetime_tz.time();

            if db_class_start_time != query_class_start_time  { // || class_time > end_time
                continue;
            }
            
            // Check frequency pattern
            match frequency {
                1 => { // Every Monday
                    if query_class_start_datetime_tz.weekday() == Weekday::Mon {
                        return Ok(true);
                    }
                },
                2 => { // Every Tuesday
                    if query_class_start_datetime_tz.weekday() == Weekday::Tue {
                        return Ok(true);
                    }
                },
                3 => { // Every Wednesday
                    if query_class_start_datetime_tz.weekday() == Weekday::Wed {
                        return Ok(true);
                    }
                },
                4 => { // Every Thursday
                    if query_class_start_datetime_tz.weekday() == Weekday::Thu {
                        return Ok(true);
                    }
                },
                5 => { // Every Friday
                    if query_class_start_datetime_tz.weekday() == Weekday::Fri {
                        return Ok(true);
                    }
                },
                6 => { // Every Saturday
                    if query_class_start_datetime_tz.weekday() == Weekday::Sat {
                        return Ok(true);
                    }
                },
                7 => { // Every Sunday
                    if query_class_start_datetime_tz.weekday() == Weekday::Sun {
                        return Ok(true);
                    }
                },
                8 => { // Every Weekday
                    match query_class_start_datetime_tz.weekday() {
                        Weekday::Mon | Weekday::Tue | Weekday::Wed | Weekday::Thu | Weekday::Fri => {
                            return Ok(true);
                        },
                        _ => {}
                    }
                },
                9 => { // Every Weekend
                    match query_class_start_datetime_tz.weekday() {
                        Weekday::Sat | Weekday::Sun => {
                            return Ok(true);
                        },
                        _ => {}
                    }
                },
                10 => { // Every Day
                    return Ok(true);
                },
                11 => { // Public Holidays - would need external holiday calendar
                    // For now, return false as we don't have holiday data
                    // In production, you'd check against a holiday calendar service
                    continue;
                },
                12 | 16 => { // One off
                    // For one-off classes, check if the datetime exactly matches the scheduled time
                    if query_class_start_datetime_tz.date() == db_class_start_datetime_tz.date() && 
                    query_class_start_time >= start_time && query_class_start_time <= end_time {
                        return Ok(true);
                    }
                },
                13 => { // Every week - same as every day within time bounds
                    return Ok(true);
                },
                14 => { // Every fortnight
                    let weeks_diff = (query_class_start_datetime_tz.date() - db_class_start_datetime_tz.date()).num_weeks();
                    if weeks_diff % 2 == 0 && weeks_diff >= 0 {
                        return Ok(true);
                    }
                },
                15 => { // Every month
                    // Check if it's the same day of month and time
                    if query_class_start_datetime_tz.day() == db_class_start_datetime.day() {
                        return Ok(true);
                    }
                },
                _ => {
                    println!("Unknown frequency code: {}", frequency);
                    continue;
                }
            }
        }
        
        println!("Class {} is not valid for timestamp {}", class_id, query_class_start_ts);
        Ok(false)
    }




    pub async fn get_class_attendance(
        &self,
        class_id: &Uuid,
        school_id: &Uuid,
        class_start_ts: i64,
    ) -> AppResult<Option<Vec<StudentClassAttendance>>> {
        let class_start_ts: CqlTimestamp = scylla::value::CqlTimestamp(class_start_ts);

        let result = self.session
            .query_unpaged(
                "SELECT user_id FROM mma.attendance WHERE class_id = ? and class_start_ts = ?",
                (class_id, class_start_ts),
            )
            .await?
            .into_rows_result().trace()?;

        // println!("Attendance query result: {:?}", result);
        let mut attending_students: Vec<Uuid> = Vec::new();
        for row in result.rows()?
        {
            let (id, ): (Uuid, ) = row.trace()?;
            attending_students.push(id);
        }
        // println!("Attendance user list result: school:{:?} {:?}", school_id, attending_students);

        let result = self.session
            .query_unpaged(
                "SELECT user_id, first_name, surname, image, school_id FROM mma.user WHERE school_id = ? ",
                (&school_id, ),
            )
            .await?
            .into_rows_result().trace()?;

        // println!("Attendance query result: {:?}", result);

        let mut attendance: Vec<StudentClassAttendance> = Vec::new();
        for row in result.rows::<(Uuid, String, String, Option<String>, Uuid), >()?
        {
            let (user_id, first_name, surname, img, user_school_id): (Uuid, String, String, Option<String>, Uuid) = row.trace()?;
            if school_id != &user_school_id {
                println!("Skipping student {} not in school {}", user_id, school_id);
                // Skip students not in the same school
                continue;
            }
            let attended = attending_students.contains(&user_id);
            // Successfully retrieved a row. Now extract the columns.
            let student_attendance = StudentClassAttendance {
                user_id,
                first_name,
                surname,
                img,
                attended
            };
            attendance.push(student_attendance);
        }


        return Ok(Some(attendance));
    }


    pub async fn get_class(&self, class_id: &Uuid, school_id: &Uuid) -> AppResult<Option<ClassData>> {
        let result = self.session
            .query_unpaged("SELECT class_id, venue_id, waiver_id, capacity, publish_mode, price, notify_booking, title, description, styles, grades, deleted_ts, free_lessons FROM mma.class where class_id = ? and school_id = ?", (class_id, school_id)) // Pass the query string and bound values
            .await?
            .into_rows_result().trace()?;

        let mut class: Option<ClassData> = None;
        for row in result.rows::<ClassDataRow>()?
        {
            let row = row.trace()?;
            // Successfully retrieved a row. Now extract the columns.
            // if publish_mode_filter.is_none() || publish_mode_filter == Some(row.publish_mode) {
            // The class is deleted
            if row.deleted_ts != Some(CqlTimestamp(0)) {
                // println!("Class is deleted");
                tracing::info!("Class is deleted");
                return Ok(None);
            }

            class = Some(ClassData {
                class_id: row.class_id,
                venue_id: row.venue_id,
                waiver_id: row.waiver_id,
                capacity: row.capacity,
                publish_mode: row.publish_mode,
                price: row.price,
                notify_booking: row.notify_booking,
                title: row.title,
                description: row.description,
                frequency: Vec::new(), // Initialize with an empty vector
                styles: Vec::new(), // Initialize with an empty vector
                grades: Vec::new(), // Initialize with an empty vector
                free_lessons: row.free_lessons,
            });
        }
        match class {
            Some(ref mut c) => {
                let class_id = c.class_id;
    
                let result = self.session
                    .query_unpaged(
                        "SELECT class_frequency_id, frequency, start_date, end_date, start_time, end_time FROM mma.class_frequency WHERE class_id = ?",
                        (class_id,),
                    )
                    .await?
                    .into_rows_result().trace()?;
    
                for row in result.rows()?
                {
                    let ( class_frequency_id, frequency, start_date, end_date, start_time, end_time) : ( Uuid, i32, NaiveDate, NaiveDate, NaiveTime, NaiveTime) = row.trace()?;
                    let class_frequency = ClassFrequencyId {
                        class_frequency_id: class_frequency_id,
                        frequency: frequency,
                        start_date: start_date,
                        end_date: end_date,
                        start_time: start_time,
                        end_time: end_time,
                    };
                    c.frequency.push(class_frequency);
                }
                return Ok(Some(c.clone()));
            }
            None => {
                // println!("No class found with ID: {}", class_id);
                return Ok(None);
            }
        }

        // return Ok(None);
    }


    pub async fn create_school(&self, super_user_id: &Uuid, school_id: &Uuid, title: &Option<String>, description: &Option<String>) -> AppResult<()> {
        // Get current timestamp
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let now = scylla::value::CqlTimestamp(now);
        let zero_ts = scylla::value::CqlTimestamp(0);

        self.session
            .query_unpaged(
                "INSERT INTO mma.school (super_user_id, school_id, title, description, created_ts, deleted_ts) VALUES (?, ?, ?, ?, ?, ?)",
                (super_user_id, school_id, title, description, now, zero_ts), // Include other fields as per your schema
            )
            .await.trace()?;

        Ok(())
    }


    pub async fn create_new_venue(&self, creator_user_id: &Uuid, venue_id: &Uuid, title: &String, description: &Option<String>, address: &Option<String>, suburb: &Option<String>, state: &Option<String>, country: &Option<String>, postcode: &Option<String>, latitude: &Option<BigDecimal>, longitude: &Option<BigDecimal>, contact_phone: &Option<String>, school_id: &Uuid) -> AppResult<()> {
        // Get current timestamp
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let now = scylla::value::CqlTimestamp(now);
        let zero_ts = scylla::value::CqlTimestamp(0);

        self.session
            .query_unpaged(
                "INSERT INTO mma.venue (venue_id, creator_user_id, title, description, created_ts, address, suburb, state, country, postcode, latitude, longitude, contact_phone, deleted_ts, school_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (venue_id, creator_user_id, title, description, now, address, suburb, state, country, postcode, latitude, longitude, contact_phone, zero_ts, school_id), // Include other fields as per your schema
            )
            .await.trace()?;

        Ok(())
    }

    pub async fn update_venue(&self, school_id: &Uuid, venue_id: &Uuid, title: &String, description: &Option<String>, address: &Option<String>, suburb: &Option<String>, state: &Option<String>, country: &Option<String>,  postcode: &Option<String>, latitude: &Option<BigDecimal>, longitude: &Option<BigDecimal>, contact_phone: &Option<String>) -> AppResult<bool> {
        // Get current timestamp

        self.session
            .query_unpaged(
                "INSERT INTO mma.venue (school_id, venue_id, title, description, address, suburb, state, country, postcode, latitude, longitude, contact_phone) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (school_id, venue_id, title, description, address, suburb, state, country, postcode, latitude, longitude, contact_phone), // Include other fields as per your schema
            )
            .await.trace()?;

        Ok(true)
    }
    

    pub async fn update_style(&self, school_id: &Uuid, style_id: &Uuid, title: &String, description: &Option<String>) -> AppResult<bool> {
        // Get current timestamp

        self.session
            .query_unpaged(
                "UPDATE mma.style SET title = ?, description = ? WHERE style_id = ? and school_id = ?",
                (title, description, style_id, school_id), // Include other fields as per your schema
            )
            .await.trace()?;

        Ok(true)
    }

    


    pub async fn get_style(&self, style_id: &Uuid, school_id: &Uuid) -> AppResult<Option<StyleData>> {
        let result = self.session
        .query_unpaged("SELECT style_id, title, description FROM mma.style where style_id = ? and school_id = ?", (style_id, school_id)) // Pass the query string and bound values
        .await?
        .into_rows_result().trace()?;

        // let mut class: Option<ClassData> = None;
        for row in result.rows::<StyleData>()?
        {
            let row = row.trace()?;
            return Ok(Some(row));
        }
        return Ok(None); // style_id not found
    }



    // get_venues
    pub async fn get_venues(&self, school_id: &Uuid) -> AppResult<Vec<VenueData>> {
        let result = self.session
            .query_unpaged(
                "SELECT venue_id, title, description, address, suburb, postcode, state, country, latitude, longitude, contact_phone FROM mma.venue where school_id = ? and deleted_ts = 0",
                (school_id, )
            )
            .await?            
            .into_rows_result().trace()?;

        let mut venues: Vec<VenueData> = Vec::new();
        for row in result.rows::<VenueData>()?
        {
            let row = row.trace()?;
            // Successfully retrieved a row. Now extract the columns.
            venues.push(row);
        }
        return Ok(venues);
    }

    // create style
    pub async fn create_style(&self, school_id: &Uuid, creator_user_id: &Uuid, style_id: &Uuid, title: &String, description: &Option<String>) -> AppResult<()> {
        // Get current timestamp
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let now = scylla::value::CqlTimestamp(now);
        let zero_ts = scylla::value::CqlTimestamp(0);

        self.session
            .query_unpaged(
                "INSERT INTO mma.style (school_id, style_id, title, description, created_ts, creator_user_id, deleted_ts) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (school_id, style_id, title, description, now, creator_user_id, zero_ts), // Include other fields as per your schema
            )
            .await.trace()?;

        Ok(())
    }

    // list styles
    pub async fn get_styles(&self, school_id: &Uuid) -> AppResult<Vec<StyleData>> {
        let mut statement = Statement::new( 
            "SELECT style_id, title, description FROM mma.style where deleted_ts = 0 and school_id = ?",
        );
        statement.set_consistency(Consistency::LocalQuorum);

        let result = self.session
            .query_unpaged(
                statement,
                (school_id, )
            )
            .await?            
            .into_rows_result().trace()?;

        let mut styles: Vec<StyleData> = Vec::new();
        for row in result.rows::<StyleData>()?
        {
            let row = row.trace()?;
            // Successfully retrieved a row. Now extract the columns.
            styles.push(row);
        }
        return Ok(styles);
    }

    

    // Add a forgotten password code for a user
    pub async fn add_forgotten_password_code(&self, email: &str, logged_user_id: Uuid, code: &str, expiry_hours: i64) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let created_ts = scylla::value::CqlTimestamp(now);

        let expires_ts = now + (expiry_hours * 60*60 * 1000);
        let expires_ts = scylla::value::CqlTimestamp(expires_ts);


        self.session
            .query_unpaged(
                "INSERT INTO mma.forgotten_password_codes (email, logged_user_id, code, expires_ts, created_ts, is_used) 
                VALUES (?, ?, ?, ?, ?, ?)",
                (
                    email, 
                    logged_user_id, 
                    code, 
                    expires_ts, 
                    created_ts, 
                    false
                ),
            )
            .await.trace()?;
        
        Ok(())
    }


    // Check if a code is valid for an email and mark it as used if it is
    pub async fn check_and_use_forgotten_password_code(&self, email: &str, code: &str) -> Result<Option<(Uuid, Uuid)>> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let now_i64 = now as i64;
        // let now = scylla::value::CqlTimestamp(now);


        let result = self.session
            .query_unpaged(
                "SELECT logged_user_id, expires_ts, is_used FROM mma.forgotten_password_codes 
                 WHERE email = ? AND code = ?",
                (email, code),
            )
            .await?
            .into_rows_result().trace()?;
        
        // Extract row data
        let mut logged_user_id: Option<Uuid> = None;
        let mut is_valid = false;
        
        for row in result.rows()? {
            let (id, expires_ts, is_used): (Uuid, CqlTimestamp, bool) = row.trace()?;
            
            // Check if code is not expired and not used
            if !is_used && expires_ts.0 > now_i64 {
                logged_user_id = Some(id);
                is_valid = true;
            }
        }
        
        // If valid, mark the code as used
        if is_valid {
            if let Some(_id) = logged_user_id {
                self.session
                    .query_unpaged(
                        "UPDATE mma.forgotten_password_codes SET is_used = true WHERE email = ? and code = ?",
                        (email, code),
                    )
                    .await.trace()?;
                

                let result = self.session
                .query_unpaged(
                    "SELECT school_id FROM mma.user WHERE logged_user_id = ?",
                    (logged_user_id,),
                )
                .await?
                .into_rows_result().trace()?;

                let mut school_id: Option<Uuid> = None;
                for row in result.rows()? {
                    let (id,): (Uuid,) = row.trace()?;
                    school_id = Some(id);
                }
                match school_id {
                    Some(id) => {
                        return Ok(Some((id, id)));
                    },
                    None => {
                        return Ok(None);
                    }
                }
            }
        }
        
        // Return None if no valid code was found
        Ok(None)
    }



    // Add a sign-up invite code for an email
    pub async fn add_sign_up_invite_code(&self, email: &str, code: &str, expiry_hours: i64, first_name: &str, surname: &str, password_hash: &String, school_id: &Option<Uuid>, new_school: bool, user_id: &Option<Uuid>) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let created_ts = scylla::value::CqlTimestamp(now);

        let expires_ts = now + (expiry_hours * 60 * 60 * 1000);
        let expires_ts = scylla::value::CqlTimestamp(expires_ts);

        self.session
            .query_unpaged(
                "INSERT INTO mma.sign_up_invite (email, code, expires_ts, created_ts, is_used, first_name, surname, password_hash, school_id, new_school, user_id) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    email, 
                    code, 
                    expires_ts, 
                    created_ts, 
                    false,
                    first_name,
                    surname,
                    password_hash,
                    school_id,
                    new_school,
                    user_id
                ),
            )
            .await.trace()?;
        
        Ok(())
    }

    // Check if an invite code is valid for an email and mark it as used if it is
    pub async fn check_and_use_sign_up_invite_code(&self, email: &str, code: &str) -> Result<(bool, Option<String>, Option<String>, Option<String>, Option<Uuid>, Option<Uuid>, bool)> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let now_i64 = now as i64;
        // let now = scylla::value::CqlTimestamp(now);

        let result = self.session
            .query_unpaged(
                "SELECT expires_ts, is_used, first_name, surname, password_hash, school_id, new_school, user_id FROM mma.sign_up_invite 
                WHERE email = ? AND code = ?",
                (email, code),
            )
            .await?
            .into_rows_result().trace()?;
        
        // Check if code exists, is not expired, and is not used
        let mut is_valid = false;
        let mut first_name: Option<String> = None;
        let mut surname: Option<String> = None;
        let mut password_hash: Option<String> = None;
        let mut school_id: Option<Uuid> = None;
        let mut new_school: bool = false;
        let mut user_id: Option<Uuid> = None;
        for row in result.rows()? {
            let (expires_ts, is_used, _first_name, _surname, _password_hash, _school_id, _new_school, _user_id): (CqlTimestamp, bool, Option<String>, Option<String>, String, Option<Uuid>, bool, Option<Uuid>) = row.trace()?;
            first_name = _first_name;
            surname = _surname;
            password_hash = Some(_password_hash);
            school_id = _school_id;
            new_school = _new_school;
            user_id = _user_id;
            // Check if code is not expired and not used
            if !is_used && expires_ts.0 > now_i64 {
                is_valid = true;
                break;
            }
        }
        
        // If valid, mark the code as used
        if is_valid {
            self.session
                .query_unpaged(
                    "UPDATE mma.sign_up_invite SET is_used = true WHERE email = ? AND code = ?",
                    (email, code),
                )
                .await.trace()?;
            
            return Ok((true, first_name, surname, password_hash, school_id, user_id, new_school));
        }
        
        // Return false if no valid code was found
        Ok((false, None, None, None, None, None, false))
    }


}
