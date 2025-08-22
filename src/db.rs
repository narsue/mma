use bigdecimal::num_bigint::BigInt;
use futures::future::Map;
use scylla::client::session::Session;
use scylla::client::session_builder::SessionBuilder;
use scylla::response::query_result::QueryResult;
use scylla::{DeserializeRow};
use scylla::statement::Statement;
use scylla::statement::prepared::PreparedStatement;
use scylla::statement::Consistency;
use std::collections::HashMap;
use std::fs;
use std::hash::Hash;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use crate::db_migrate::MigrationTool;
use crate::models::Permissions;
use crate::payment_plan::{*};
use bigdecimal::ToPrimitive;

use std::sync::Arc;
use uuid::Uuid;
use std::time::SystemTime;
use rand::{distributions::Alphanumeric, Rng};
use chrono::{Datelike, Timelike, Duration, NaiveDate, NaiveDateTime, NaiveTime, DateTime, TimeZone, Utc, Weekday};
use chrono_tz::Tz;
use scylla::value::CqlTimestamp;
use bigdecimal::BigDecimal;
use crate::db;
use crate::error::{AppError, Result, Result as AppResult, TraceErr};
use crate::api::{ActivePaymentPlanData, ClassData, ClassFrequency, ClassFrequencyId, 
    PurchasablePaymentPlanData, SchoolUserId, StudentClassAttendance, StyleData, UpdateUserProfileRequest, 
    UserProfileData, UserWithName, VenueData, SchoolUpdatePaymentPlanRequest, UserSubscribePaymentPlan,
    ChangeUserSubscribePaymentPlan, SchoolUser, UserSchoolPermission, DetailedSchoolUserId, DashStat,
    ClassHistoryRecord, ClassHistoryStats, PaymentInfo}; 
use crate::stripe_client::StripeClient;
use ammonia::clean;
use lazy_static::lazy_static;
use regex::Regex;
use email_address::EmailAddress;
use tokio::task;

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};


/// First strip any HTML/JS/etc tags, attributes, entities, etc.
fn strip_html(input: &str) -> String {
    clean(input)
}

/// Sanitize a person’s name: allow letters, spaces, hyphens and apostrophes.
fn sanitize_name(input: &str, max_len: usize) -> String {
    lazy_static! {
        static ref RE: Regex = Regex::new(r#"[^A-Za-z\s\-']"#).unwrap();
    }
    let s = strip_html(input);
    let filtered = RE.replace_all(&s, "");
    let trimmed = filtered.trim();
    trimmed.chars().take(max_len).collect()
}

/// Sanitize an address: allow letters, digits, spaces, “.,-#/” and apostrophes.
fn sanitize_address(input: &str, max_len: usize) -> String {
    lazy_static! {
        static ref RE: Regex = Regex::new(r#"[^A-Za-z0-9\s\.\,\-\'\#\/]"#).unwrap();
    }
    let s = strip_html(input);
    let filtered = RE.replace_all(&s, "");
    let trimmed = filtered.trim();
    trimmed.chars().take(max_len).collect()
}

/// Sanitize a phone number: allow digits, spaces, “()+-”
fn sanitize_phone(input: &str, max_len: usize) -> String {
    lazy_static! {
        static ref RE: Regex = Regex::new(r#"[^0-9\s\+\-\(\)]"#).unwrap();
    }
    let s = strip_html(input);
    let filtered = RE.replace_all(&s, "");
    let trimmed = filtered.trim();
    trimmed.chars().take(max_len).collect()
}

/// Sanitize a phone number: allow digits, spaces, “()+-”
fn sanitize_gender(input: &str) -> String {
    if input.to_lowercase() == "male" {
        return "male".to_string();
    }
    if input.to_lowercase() == "female" {
        return "female".to_string();
    }
    return "".to_string();
}

fn sanitize_email(input: &String) -> Option<String> {
    let s = strip_html(input);
    let t = s.trim();
    let email = EmailAddress::from_str(s.as_str());
    match email {
        Ok(email) => Some(email.to_string()),
        Err(_) => None, // Return None if parsing fails
    }

    // EmailAddress::parse enforces RFC-compliance and lowercases the domain
    // EmailAddress::parse(t).ok().map(|e| e.to_string())
}


/// Truncates a timestamp (in milliseconds) to the start of the given StatWindow.
pub fn truncate_timestamp(ts_millis: i64, window: StatWindow) -> i64 {
    let dt = Utc.timestamp_millis_opt(ts_millis).unwrap();

    let truncated = match window {
        StatWindow::HOUR => dt
            .with_minute(0)
            .unwrap()
            .with_second(0)
            .unwrap()
            .with_nanosecond(0)
            .unwrap(),

        StatWindow::DAY => dt
            .with_hour(0)
            .unwrap()
            .with_minute(0)
            .unwrap()
            .with_second(0)
            .unwrap()
            .with_nanosecond(0)
            .unwrap(),

        StatWindow::WEEK => {
            // Start of the ISO week (Monday)
            let num_days_from_monday = dt.weekday().num_days_from_monday() as i64;
            let start_of_week = dt.date_naive() - Duration::days(num_days_from_monday);
            Utc.with_ymd_and_hms(start_of_week.year(), start_of_week.month(), start_of_week.day(), 0, 0, 0).unwrap()
        }

        StatWindow::MONTH => {
            Utc.with_ymd_and_hms(dt.year(), dt.month(), 1, 0, 0, 0).unwrap()
        }

        StatWindow::YEAR => {
            Utc.with_ymd_and_hms(dt.year(), 1, 1, 0, 0, 0).unwrap()
        },

        StatWindow::ALL => {
            return 0;
        }
    };

    truncated.timestamp_millis()
}


pub fn age_check(age_years: Option<i32>, min_age: Option<i32> , max_age: Option<i32>) -> bool 
{
    match age_years {
        Some(age_years) => {
            if min_age.is_some() && max_age.is_some() {
                if min_age.unwrap() <= age_years && age_years <= max_age.unwrap() {
                    return true;
                }
                return false;
            } else if min_age.is_some() {
                if min_age.unwrap() <= age_years {
                    return true;
                }
                return false;    
            } else if max_age.is_some() {
                if age_years <= max_age.unwrap() {
                    return true;
                } 
                else {
                    return false;
                }      
            } else {
                return true;
            }
            return false;
        },
        None => {
            if min_age.is_none() && max_age.is_none() {
                return true;
            }
            return false
        },
    };
}

pub fn get_age(dob_str: &Option<String>) -> Option<i32> {
    match dob_str {
        Some(dob_str) => {
            match NaiveDate::parse_from_str(&dob_str, "%Y/%m/%d") {
                Ok(dob) => {
                    // Valid format
                    let today = Utc::now().date_naive();
    
                    let mut age = today.year() - dob.year();
                    if age < 0 {
                        return None;
                    }
                    return Some(age);
                },
                Err(_) => {
                    return None;
                }
            }
        },
        None => { None }
    }
}

pub fn get_naive_age(dob_date: &Option<NaiveDate>) -> Option<i32> {
    let now = Utc::now();
    match dob_date {
        Some(dob_date) => {
            let mut age = now.year() - dob_date.year();
            if age < 0 {
                return None;
            }
            return Some(age);
        },
        None => { None }
    }
}

pub struct UserPaymentPlan {
    pub user_payment_plan_id: Uuid,
    pub base_payment_plan_id: Uuid,
    pub payment_plan_id: Uuid,
    pub group_user_ids: Vec<Uuid>,
    pub next_group_user_ids: Vec<Uuid>, 
    pub expiration_ts: i64, 
    pub subscribed: bool
}


#[derive(DeserializeRow)]
pub struct PaymentPlanData {
    payment_plan_id: Uuid,
    base_payment_plan_id: Uuid,
    grouping_id: i32,
    min_age: Option<i32>,
    max_age: Option<i32>,
    working: Option<bool>,
    title: String,
    description: String,
    cost: BigDecimal,
    duration_id: i32,
}

#[derive(DeserializeRow)]
struct UserRow {
    user_id: Uuid,           // 0: uuid (PK, assumed non-null by deserializer)
    email: Option<String>,           // 1: text (assumed non-null)
    first_name: String,      // 3: text (assumed non-null)
    surname: String,         // 4: text (assumed non-null)
    gender: Option<String>,  // 5: text (nullable)
    phone: Option<String>,   // 6: text (nullable)
    dob: Option<NaiveDate>,     // 7: text (nullable - consider Date type if stored as such)
    dev_stripe_payment_method_ids: Option<Vec<String>>, // 8: text (nullable)
    prod_stripe_payment_method_ids: Option<Vec<String>>, // 8: text (nullable)
    email_verified: Option<bool>,    // 10: boolean (assumed non-null)
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

fn calculate_age(dob_str: &String) -> Option<i32> {
    let dob = NaiveDate::parse_from_str(dob_str, "%Y/%m/%d").ok();
    let dob = match dob {
        Some(dob) => dob,
        None => {
            tracing::error!("Dob string for user is invalid: {}", dob_str);
            return None;
        }
    };

    let today = Utc::now().date_naive();

    let mut age = today.year() - dob.year();

    // Subtract one if birthday hasn't occurred yet this year
    if (today.month(), today.day()) < (dob.month(), dob.day()) {
        age -= 1;
    }

    Some(age)
}


pub fn get_time() -> i64
{
    SystemTime::now()
    .duration_since(SystemTime::UNIX_EPOCH)
    .unwrap_or_default()
    .as_millis() as i64
}

// Default bscrypt 27 hashes / per second 
// Default Argon2 130 hashes / per second
pub fn hash_password(password: &str) -> Result<String> {
    // Generate a random salt
    let salt = SaltString::generate(&mut OsRng);
    
    // Configure Argon2 with default parameters
    // let argon2 = Argon2::default();
    // Set custom, slightly lower parameters
    // let params = argon2::Params::new(
    //     1024*19, // memory_cost (2 MiB instead of 4)
    //     2,    // time_cost (2 iterations instead of 3)
    //     1,    // parallelism
    //     None, // output length (default)
    // ).map_err(|e| AppError::Internal(format!("Argon2 params error: {}", e)))?;

    // let argon2 = Argon2::new(
    //     argon2::Algorithm::Argon2id,
    //     argon2::Version::V0x13,
    //     params,
    // );

    let params = argon2::Params::new(
        1024*7, // memory_cost (2 MiB instead of 4)
        5,    // time_cost (2 iterations instead of 3)
        1,    // parallelism
        None, // output length (default)
    ).map_err(|e| AppError::Internal(format!("Argon2 params error: {}", e)))?;

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    );

    
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
    migration.migrate_to_version(session, 1).await.trace()?;

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

    pub async fn get_logged_user_by_email(&self, email: &String) -> Result<Option<(Uuid, String)>> {
        // First, get the user_id from the email lookup table
        let email_result = self.session
            .execute_unpaged(
                // "SELECT user_id, password_hash FROM mma.user_by_email WHERE email = ?",
                &self.select_user_by_email_stmt.clone(),
                (email,),
            )
            .await.trace()?
            .into_rows_result().trace()?;
        // let email_result = self.session
        //     .query_unpaged(
        //         "SELECT logged_user_id, password_hash FROM mma.logged_user WHERE email = ?",
        //         (email,),
        //     )
        //     .await.trace()?
        //     .into_rows_result().trace()?;
        for row in email_result.rows().trace()?
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
            .await.trace()?
            .into_rows_result().trace()?;
        
        let mut school_ids = Vec::new();
        for row in result.rows::<(Vec<(Uuid, Uuid)>,)>().trace()? {
            let (schools,): (Vec<(Uuid, Uuid)>,) = row.trace()?;
            school_ids.extend(schools.into_iter().map(|(school_id, user_id)| SchoolUserId { school_id, user_id }));
        }
        return Ok(school_ids);
    }

    pub async fn get_school_user_titles(&self, school_users: &Vec<SchoolUserId>) -> Result<Vec<DetailedSchoolUserId>> {
        let mut school_ids = Vec::new();
        let mut user_ids = Vec::new();
        let mut return_val = Vec::new();

        for school_user in school_users {
            school_ids.push(&school_user.school_id);
            user_ids.push(&school_user.user_id);
        }
        let mut user_name_map = HashMap::new();
        let mut school_title_map = HashMap::new();


        let result = self.session
            .query_unpaged(
                "SELECT school_id, title FROM mma.school WHERE school_id in ?",
                (&school_ids,),
            )
            .await.trace()?
            .into_rows_result().trace()?;

        for row in result.rows().trace()? {
            let (school_id, title): (Uuid, Option<String>) = row.trace()?;
            let title = match title {
                Some(title) => title,
                None => "Unnamed school".to_string()
            };
            school_title_map.insert(school_id, title);
        }

        let result = self.session
            .query_unpaged(
                "SELECT user_id, first_name, surname FROM mma.user WHERE user_id in ?",
                (&user_ids,),
            )
            .await.trace()?
            .into_rows_result().trace()?;

        for row in result.rows().trace()? {
            let (user_id, first_name, surname): (Uuid, Option<String>, Option<String>) = row.trace()?;
            let first_name = match first_name {
                Some(first_name) => first_name,
                None => "n/a".to_string()
            };
            let surname = match surname {
                Some(surname) => surname,
                None => "n/a".to_string()
            };
            let mut name = first_name;
            name.push_str(" ");
            name.push_str(&surname);

            user_name_map.insert(user_id, name);
        }


        for school_user in school_users {
            school_ids.push(&school_user.school_id);
            user_ids.push(&school_user.user_id);
            let name = user_name_map.get(&school_user.user_id);
            let name = match name {
                Some(name) => name,
                None => &"n/a".to_string()
            };
            let title = school_title_map.get(&school_user.school_id);
            let title = match title {
                Some(title) => title,
                None => &"n/a".to_string()
            };

            return_val.push(DetailedSchoolUserId{
                school_id: school_user.school_id,
                user_id: school_user.user_id,
                user_name: name.clone(),
                school_title: title.clone()
            });
        }            

        return Ok(return_val);
    }


    pub async fn get_user_permissions(&self, user_id: &Uuid) -> Result<Vec<UserSchoolPermission>> {
        let result = self.session
            .query_unpaged(
                "SELECT club_id, class_id, permission FROM mma.user_permission WHERE user_id = ?",
                (user_id,),
            )
            .await.trace()?
            .into_rows_result().trace()?;
        
        let mut permissions = Vec::new();
        let zero_guuid = Uuid::nil();

        for row in result.rows().trace()? {
            let (club_id, class_id, permission): (Uuid, Uuid, i32) = row.trace()?;
            let matcha= (club_id == zero_guuid);
            let club_id = match club_id {
                matcha => {None},
                _ => Some(club_id)
            };
            let matcha= (class_id == zero_guuid);
            let class_id: Option<Uuid> = match class_id {
                matcha => {None},
                _ => Some(class_id)
            };

            permissions.push(UserSchoolPermission{
                club_id,
                class_id,
                permission
            });
        }
        return Ok(permissions);
    }

    // Verify a session token and return the user ID if valid
    pub async fn verify_session(&self, logged_user_id: &Uuid, session_token: &str) -> Result<(bool, i64, Option::<Vec<SchoolUserId>>)> {
        // println!("Verifying session: {}", session_token);
        let result = self.session
            .query_unpaged(
                "SELECT expires_ts, is_active FROM mma.session WHERE session_token = ? and logged_user_id = ?",
                (session_token, logged_user_id),
            )
            .await.trace()?
            .into_rows_result().trace()?;

        

        for row in result.rows().trace()?
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
                tracing::info!("Found expired session info for {} {} {}", logged_user_id, session_token, is_active);

                return Ok((false, 0, None)); // Session expired or inactive
            }
        }
        tracing::info!("Did not find session info for {} {}", logged_user_id, session_token);
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
        email: &String,
        password: Option<&str>,
        password_hash: Option<&str>,
        first_name: &str,
        surname: &str,
        email_verified: bool,
        school_id: &Option<Uuid>,
        _user_id: &Option<Uuid>,
        new_school: bool
    ) -> Result<(Option<Uuid>, Uuid)> {


        // if let Ok(_) = email_check.first_row() {
        //     return Err(AppError::Internal(format!("Email {} is already registered", email)));
        // }
        

        let email = match sanitize_email(email) {
            Some(email) => {
                if email.len() == 0 {
                    return Err(AppError::BadRequest("User email cannot be empty".to_string()));
                }
                email
            },
            None => {
                return Err(AppError::BadRequest("User email is invalid".to_string()));
            }
        };

        let first_name = sanitize_name(&first_name, 50);
        let surname = sanitize_name(&surname, 50);



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

        let logged_user_id = self.get_logged_user_by_email(&email).await.trace()?;
        let mut logged_user_id = match logged_user_id {
            Some((logged_user_id, _)) => Some(logged_user_id),
            None => None
        };

        // Insert main user record
        match _user_id
            { Some(_user_id) => {
                self.session
                .query_unpaged(
                    "update mma.user set email_verified = ? where user_id = ?",
                    (
                        email_verified,
                        user_id,
                    ),
                )
                .await
                .trace_err("Updating db user")?;
            },
            None => {
                // Check if email already exists using the email lookup table - should only trigger on creating a new school
                let result = self.session
                    .query_unpaged(
                        "SELECT user_id FROM mma.user WHERE email = ?",
                        (&email,),
                    )
                    .await.trace()?
                    .into_rows_result().trace()?;

                
                for row in result.rows().trace()?
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
                            &email,
                            first_name,
                            surname,
                            now,
                            email_verified,
                            school_id
                        ),
                    )
                    .await
                    .trace_err("creating db user")?;

                // Increment user count for dashboard stats
                if let Err(e) = self.increment_user_count(&school_id).await {
                    tracing::error!("Failed to increment user count: {:?}", e);
                }
                

                if new_school {
                    self.create_school(&user_id, &school_id, &None, &None).await.trace()?;
                }
            }
        }

        
        match logged_user_id {
            Some(logged_user_id) => {
                self.adjust_logged_user_school_user_id(&school_id, &logged_user_id, &user_id, true).await.trace()?;
            },
            None => {
                logged_user_id = Some(Uuid::new_v4());
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
            }
        };

        // Insert into email lookup table
        // self.session
        //     .query_unpaged(
        //         "INSERT INTO mma.user_by_email (email, user_id, password_hash) VALUES (?, ?, ?)",
        //         (email, user_id, &password_hash),
        //     )
        //     .await.trace()?;
        
        Ok((logged_user_id, user_id))
    }

    pub async fn adjust_logged_user_school_user_id(
        &self,
        school_id: &Uuid,
        logged_user_id: &Uuid,
        user_id: &Uuid,
        add_access: bool
    ) -> AppResult<()> {
        // Check the user id exists
        let result = self.session
            .query_unpaged(
                "SELECT school_id FROM mma.user WHERE user_id = ?",
                (user_id,),
            )
            .await.trace()?
            .into_rows_result().trace()?;
        
        for row in result.rows().trace()?
        {
            let (ref_shool_id,) : (Uuid, ) = row.trace()?;
            if ref_shool_id != *school_id {
                return Err(AppError::BadRequest("School user id has the wrong school id for adjustment".to_string()));
            }
        }
        if result.rows_num() == 0 {
            return Err(AppError::BadRequest("School user does not exist".to_string()));
        }


        // Check the logged user id exists
        let result = self.session
            .query_unpaged(
                "SELECT logged_user_id FROM mma.logged_user WHERE logged_user_id = ?",
                (logged_user_id,),
            )
            .await.trace()?
            .into_rows_result().trace()?;
        
        if result.rows_num() == 0 {
            return Err(AppError::BadRequest("logged_user_id does not exist".to_string()));
        }


        let mut school_user_ids = Vec::new();
        school_user_ids.push((school_id, user_id));
        let add_symbol = match add_access {
            true => "+",
            false => "-"
        };

        self.session
            .query_unpaged(
                format!("update mma.logged_user SET school_user_ids = school_user_ids {} ? where logged_user_id = ?", add_symbol),
                (
                    &school_user_ids,
                    logged_user_id,
                ),
            )
            .await
            .trace_err("Updating logged_user")?;

        Ok(())
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
            .await.trace()?
            .into_rows_result().trace()?;
        
        for row in result.rows::<UserRow>().trace()?
        {
            let row: UserRow = row.trace()?;
            let stripe_payment_method_id = if self.dev_mode {
                row.dev_stripe_payment_method_ids
            } else {
                row.prod_stripe_payment_method_ids
            };
            let stripe_payment_method_ids = match stripe_payment_method_id {
                Some(ids) => ids,
                None => Vec::new(), // Default to empty vector if None
            };

            let mut email_verified = match row.email_verified {
                Some(email_verified) => email_verified,
                None => false
            };
            let dob_str = match row.dob{
                Some(dob) => {
                    Some(dob.to_string())
                },
                None => {
                    None
                }
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
                dob: dob_str,
                stripe_payment_method_ids: stripe_payment_method_ids,
                email_verified: email_verified, 
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
    pub async fn update_user_profile(
        &self, 
        user_id: &Uuid, 
        school_id: &Uuid, 
        update_data: &UpdateUserProfileRequest
    ) -> Result<()> {

        let mut ref_user_id = *user_id;
        if update_data.first_name.len() == 0 {
            return Err(AppError::BadRequest("User first name cannot be empty".to_string()));
        }
        if update_data.surname.len() == 0 {
            return Err(AppError::BadRequest("User surname cannot be empty".to_string()));
        }
        let email = match update_data.email {
            Some(ref email) => {
                let email = sanitize_email(&email);
                match email {
                    Some(email) => {
                        if email.len() == 0 {
                            return Err(AppError::BadRequest("User email cannot be empty".to_string()));
                        }
                        Some(email)
                    },
                    None => {
                        return Err(AppError::BadRequest("User email is invalid".to_string()));
                    }
                }
            },
            None => {
                None
            }
        };
        
        if *user_id == Uuid::nil() {
            ref_user_id = Uuid::new_v4();
        } else {
            // Check the user exists before allowing an edit / Because update on scylla will add a user if it doesnt exist
            let result = self.session
                .query_unpaged(
                    "SELECT school_id FROM mma.user WHERE user_id = ?",
                    (ref_user_id,),
                )
                .await.trace()?            
                .into_rows_result().trace()?;
            
            if result.rows_num() != 1 {
                return Err(AppError::BadRequest("User does not exist".to_string()));
            }

            for row in result.rows().trace()?
            {
                let (ref_school_id,): (Uuid,) = row.trace()?;
                if ref_school_id != *school_id {
                    return Err(AppError::BadRequest("User does not have the school id of the change".to_string()));
                }
            }

        }

        let first_name = sanitize_name(&update_data.first_name, 50);
        let surname = sanitize_name(&update_data.surname, 50);
        let address = sanitize_address(&update_data.address.as_deref().unwrap_or_default(), 150);
        let suburb = sanitize_address(&update_data.suburb.as_deref().unwrap_or_default(), 50);
        let phone = sanitize_phone(&update_data.phone.as_deref().unwrap_or_default(), 20);
        let emergency_name = sanitize_name(&update_data.emergency_name.as_deref().unwrap_or_default(), 50);
        let emergency_phone = sanitize_phone(&update_data.emergency_phone.as_deref().unwrap_or_default(), 20);
        let emergency_medical = sanitize_address(&update_data.emergency_medical.as_deref().unwrap_or_default(), 150);
        let belt_size = sanitize_address(&update_data.belt_size.as_deref().unwrap_or_default(), 30);
        let uniform_size = sanitize_address(&update_data.uniform_size.as_deref().unwrap_or_default(), 30);
        let emergency_relationship = sanitize_address(&update_data.emergency_relationship.as_deref().unwrap_or_default(), 50);
        let gender = sanitize_gender(update_data.gender.as_deref().unwrap_or_default());

        let dob = match get_age(&update_data.dob){
            Some(age_years) => {
                update_data.dob.clone()
            },
            None => {
                None
            }
        };


        self.session
            .query_unpaged(
                "UPDATE mma.user \
                SET first_name = ?, surname = ?, gender = ?, phone = ?, dob = ?, \
                address = ?, suburb = ?, emergency_name = ?, emergency_relationship = ?, \
                emergency_phone = ?, emergency_medical = ?, belt_size = ?, uniform_size = ?, \
                school_id = ?, email = ? WHERE user_id = ?",
                (
                    &first_name,
                    &surname,
                    gender, // Send "" for None
                    phone,
                    dob,
                    address,
                    suburb,
                    emergency_name,
                    emergency_relationship,
                    emergency_phone,
                    emergency_medical,
                    belt_size,
                    uniform_size,
                    school_id,
                    &email,
                    ref_user_id,
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
            .await.trace()?            
            .into_rows_result().trace()?;

        for row in result.rows().trace()?
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
            .await.trace()?            
            .into_rows_result().trace()?;

        for row in result.rows().trace()?
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
            .await.trace()?
            .into_rows_result().trace()?;          
            
        if result.rows_num() == 0 {
            // println!("No waiver found with ID: {}", waiver_id);
            return Ok(None);
        }
        
        for row in result.rows().trace()?
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
        let timezone_str = self.get_timezone(school_id, None).await.trace()?;

        let zero_ts = scylla::value::CqlTimestamp(0);
        self.session
            .query_unpaged(
                "INSERT INTO mma.class (school_id, creator_user_id, class_id, title, description, created_ts, venue_id, publish_mode, capacity, notify_booking, price, waiver_id, styles, grades, deleted_ts, timezone) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (school_id, creator_user_id, class_id, title, description, now, venue_id, publish_mode, capacity, notify_booking, price, waiver_id, style_ids, grading_ids, zero_ts, timezone_str), 
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
            .await.trace()?
            .into_rows_result().trace()?;

        let mut delete_class_frequency_ids: Vec<Uuid> = Vec::new();
        for row in result.rows().trace()?
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
            .await.trace()?
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
            .await.trace()?
            .into_rows_result().trace()?;

            for row in result.rows().trace()?
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
            .await.trace()?
            .into_rows_result().trace()?;

        for row in result.rows().trace()? {
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
            .await.trace()?
            .into_rows_result().trace()?;

        for row in result.rows().trace()? {
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
            .await.trace()?
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
            .await.trace()?
            .into_rows_result().trace()?;

        if result.rows_num() > 0 {
            return Ok(true); // User has accepted the waiver
        }
        Ok(false) // User has not accepted the waiver
    }



    // pub async fn get_class_attendance_count(
    //     &self,
    //     class_id: &Uuid,
    //     class_start_ts: i64
    // } -> AppResult<i32> { 

    //     let cql_class_start_ts = scylla::value::CqlTimestamp(class_start_ts);
    //     let result = self.session
    //         .query_unpaged(
    //             "SELECT count(user_id) FROM mma.attendance WHERE class_id = ? and class_start_ts = ?",
    //             (class_id, query_class_start_ts_cql),
    //         )
    //         .await.trace()?
    //         .into_rows_result().trace()?;


    //     let mut student_attend_count: i64 = 0;
    //     for row in result.rows().trace()? {
    //         let (count,): (i64,) = row.trace()?;
    //         student_attend_count = count;
    //     }
    //     return 
    // }



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
            .await.trace()?
            .into_rows_result()
            .trace_err("Getting db attending_count")?;

        for row in result.rows::<(i32,)>().trace()? {
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
            .await.trace()?
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



    pub async fn pay_with_user_method (
        &self,
        user_id: &Uuid,
        school_id: &Uuid,
        class_id: Option<&Uuid>,
        stripe_payment_method_ids: Option<Vec<String>>, 
        stripe_customer_id: Option<String>,
        description: String,
        price: &BigDecimal,
        now: i64,
        class_start_ts: Option<i64>,
        stripe_client: &StripeClient,
        expiration_ts: Option<i64>,
        group_members: &Vec<&Uuid>,
        base_payment_plan_id: Option<&Uuid>,
        payment_plan_id: Option<&Uuid>,
    ) -> AppResult<bool> {
        let is_pass = class_id.is_none();
        if is_pass {
            if expiration_ts.is_none() {
                tracing::error!("Attempting to use a expiration_ts that has no value");
                return Ok(false);
            }
        }
        // Try individuals payment methods first
        match stripe_customer_id {
            Some(stripe_customer_id) => {
                match stripe_payment_method_ids {
                    Some(stripe_payment_method_ids) => {
                        for payment_method_id in stripe_payment_method_ids {
                            let transaction_id = Uuid::new_v4();
                            // let description = format!("Casual attendance of class:{}", class_id);
                            let currency = "aud";
                            // let amount = price*BigDecimal::from(100);
                            let cents_i64 = (price * BigDecimal::from(100))
                                .round(0)
                                .to_i64()
                                .unwrap();

                            let mut stripe_payment_id = None;
                            if *price > BigDecimal::from(0) { 
                                // return Ok(true);

                                let result = stripe_client.charge_payment_method(cents_i64, currency, &payment_method_id, &stripe_customer_id, &transaction_id, school_id, user_id, Some(&description)).await.trace()?;
                                // result.id
                                stripe_payment_id = Some(result.id);
                            }

                            // let duration = PaymentPlanDuration::SingleClass as i32;
                            let payment_status = 1; // captured

                            let zero_guuid = Uuid::nil();
                            let now = scylla::value::CqlTimestamp(now);

                            let class_start_ts = match class_start_ts {
                                Some(class_start_ts) => Some(scylla::value::CqlTimestamp(class_start_ts)),
                                None => None
                            };

                            let base_payment_plan_id = match base_payment_plan_id {
                                Some(base_payment_plan_id) => {base_payment_plan_id},
                                None => &zero_guuid
                            };
                            
                            
                            let user_payment_plan_id = match class_id {
                                Some(_) => None,
                                None => {Some(Uuid::new_v4())}
                            };

                            let payment_plan_id = match payment_plan_id {
                                Some(payment_plan_id) => {payment_plan_id},
                                None => &zero_guuid
                            };

                            let class_id = match class_id {
                                Some(class_id) => class_id,
                                None => &zero_guuid
                            };

                            let class_start_ts = match class_start_ts {
                                Some(class_start_ts) => class_start_ts,
                                None => {scylla::value::CqlTimestamp(0)}
                            };

                            let _result = self.session
                                .query_unpaged("insert into mma.user_payment (user_id, base_payment_plan_id, payment_plan_id, class_id, class_start_ts, created_ts, stripe_payment_id, captured_ts, captured, status) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", 
                                (user_id, base_payment_plan_id, payment_plan_id, class_id, class_start_ts, now, stripe_payment_id, now, price, payment_status)) // Pass the query string and bound values
                                .await.trace()?;


                            if is_pass {
                                //CREATE TABLE IF NOT EXISTS {}.user_payment_plan (user_payment_plan_id uuid, user_id uuid, base_payment_plan_id uuid, payment_plan_id uuid, group_user_ids set<uuid>, next_group_user_ids set<uuid>, created_ts timestamp, expiration_ts timestamp, subscribed boolean, PRIMARY KEY(user_id, user_payment_plan_id));
                                let expiration_ts = match expiration_ts {
                                    Some(ts) => scylla::value::CqlTimestamp(expiration_ts.unwrap()),
                                    None => {
                                        tracing::error!("Attempting to use a expiration_ts that has no value. This code should never run.");
                                        scylla::value::CqlTimestamp(0)
                                    }
                                };

                                let _result = self.session
                                    .query_unpaged("insert into mma.user_payment_plan (user_payment_plan_id, user_id, base_payment_plan_id, payment_plan_id, group_user_ids, next_group_user_ids, created_ts, expiration_ts, subscribed) values (?, ?, ?, ?, ?, ?, ?, ?, ?)", 
                                    (user_payment_plan_id, user_id, base_payment_plan_id, payment_plan_id, group_members, group_members, now, expiration_ts, true)) // Pass the query string and bound values
                                    .await.trace()?;

                                let mut add_active = Vec::new();
                                if user_payment_plan_id.is_some()
                                {
                                    add_active.push((user_payment_plan_id.unwrap(), expiration_ts));
                                }
                                // Lets add the pass to the active plans
                                for ref_user_id in group_members {
                                    let result = self.session
                                        .query_unpaged("UPDATE mma.user SET active_payment_plans = active_payment_plans + ? WHERE user_id = ?", 
                                        (&add_active, ref_user_id)) 
                                        .await.trace()?;  
                                }
                            }
                            tracing::warn!("Pay method - success");

                            return Ok(true);
                            // CREATE TABLE IF NOT EXISTS {}.user_payment (user_payment_id uuid, user_id uuid, class_id uuid, class_start_ts timestamp, base_payment_plan_id uuid, payment_plan_id uuid, status int, stripe_payment_id text, created_ts timestamp, paid decimal, amount decimal, refunded decimal, refunded_ts timestamp, paid_ts timestamp, processing_ts timestamp, processing_node text, captured_ts timestamp, captured decimal, PRIMARY KEY (user_id, base_payment_plan_id, class_id, class_start_ts));

                        }
                    }, 
                    None => {}
                }
            }, 
            None => {}
        }
        tracing::warn!("Pay method - failed");
        Ok(false)
    }

    pub async fn get_timezone(
        &self,
        school_id: &Uuid,
        class_id: Option<Uuid>,
    ) -> AppResult<String> {
        let (table_name, field_name, id) = match &class_id {
            Some(class_id) => ("class", "class_id", class_id),
            None => ("school", "school_id", school_id)
        };

        let result = self.session
            .query_unpaged(
                format!("SELECT timezone FROM mma.{} WHERE {} = ?", table_name, field_name),
                (id,),
            )
            .await.trace()?
            .into_rows_result().trace()?;   

        // Check if the class exists and is not deleted
        if result.rows_num() == 0 {
            return Err(AppError::Internal("No class exists".to_string()));
        }

        for row in result.rows().trace()? {
            let (db_timezone, ): (Option<String>, ) = row.trace()?;
            let db_timezone = match db_timezone {
                Some(db_timezone) => db_timezone,
                None => "Australia/Sydney".to_string()
            };
            return Ok(db_timezone);
        }

        return Err(AppError::Internal("No class exists".to_string()));
    }


    pub async fn get_expiration_ts(
        &self,
        school_id: &Uuid,
        class_id: Option<Uuid>,
        now: i64,
        duration_id: i32,
    ) -> AppResult<i64> {

        // Query the database
        let timezone_str = self.get_timezone(school_id, class_id).await.trace()?;
    
        // Parse timezone string
        let tz: Tz = timezone_str
            .parse()
            .map_err(|_| AppError::Internal(format!("Invalid timezone: {}", timezone_str)))?;
    
        // Convert `now` (timestamp) to `DateTime<Utc>` and then to local time
        let now_dt_utc: DateTime<Utc> = Utc
            .timestamp_opt(now / 1000, 0)
            .single()
            .ok_or_else(|| AppError::Internal("Invalid 'now' timestamp".to_string()))?;
    
        let now_local = now_dt_utc.with_timezone(&tz);
        let current_date_local = now_local.date_naive();

        if duration_id == PaymentPlanDuration::CalenderMonth as i32 {
            // Get the year and month
            let (year, month) = (current_date_local.year(), current_date_local.month());

            // Determine the first day of the next month
            let (next_year, next_month) = if month == 12 {
                (year + 1, 1)
            } else {
                (year, month + 1)
            };

            // Construct the start of the next month at midnight
            let start_of_next_month = tz
                .with_ymd_and_hms(next_year, next_month, 1, 0, 0, 0)
                .single()
                .ok_or_else(|| AppError::Internal("Failed to create next month datetime".to_string()))?;

            // Convert to UTC and get the timestamp (in seconds)
            let expiration_ts = start_of_next_month.with_timezone(&Utc).timestamp() * 1000;
            tracing::info!("Expiration ts calc {:?} {:?} {:?}",now,expiration_ts, start_of_next_month);

            if expiration_ts < now {
                return Err(AppError::Internal("Calculation of month end timestamp is before the now timestamp".to_string()))
            }
            return Ok(expiration_ts);
        }

        // Query the database
        let result = self.session
            .query_unpaged(
                "SELECT end_dates FROM mma.time_span WHERE school_id = ? AND duration_id = ?",
                (school_id, duration_id),
            )
            .await
            .trace()?
            .into_rows_result()
            .trace()?;
    
        // Look for the first end_date > now
        for row in result.rows().trace()? {
            let (end_dates,): (Vec<NaiveDate>,) = row.trace()?;
            if let Some(next_end_date) = end_dates.into_iter().find(|&d| d > current_date_local) {
                // Convert NaiveDate to DateTime in local TZ
                let local_dt = tz
                    .from_local_datetime(&next_end_date.and_hms_opt(0, 0, 0).unwrap())
                    .single()
                    .ok_or_else(|| {
                        AppError::Internal(format!(
                            "Ambiguous or invalid local datetime: {} in {}",
                            next_end_date, timezone_str
                        ))
                    })?;
    
                // println!("Expiration_ts: {}", local_dt.timestamp());

                // Return Unix timestamp
                return Ok(local_dt.timestamp() * 1000);
            }
        }
    
        Err(AppError::Internal(format!(
            "No valid future time_spans defined for duration_id {}",
            duration_id
        )))
    }


    pub async fn pay_pass (
        &self,
        user_id: &Uuid,
        school_id: &Uuid,
        stripe_client: &StripeClient,
        price: &BigDecimal,
        base_payment_plan_id: &Uuid,
        payment_plan_id: &Uuid,
        duration_id: i32,
        grouping_id: i32,
        group_members: &Vec<&Uuid>,
    ) -> AppResult<bool> {
        
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
            return Err(AppError::Internal(format!("User with ID {} does not exist", user_id)));
        }

        for row in result.rows().trace()? {
            // let mut expired_active_plans = Vec::new();

            let (ref_school_id, active_payment_plans, payment_provider, stripe_payment_method_ids, stripe_customer_id): (Uuid, Option<Vec<(Uuid, CqlTimestamp)>>, Option<Uuid>, Option<Vec<String>>, Option<String>) = row.trace()?;
            if ref_school_id != *school_id {
                return Err(AppError::Internal(format!("User Id {} has wrong school ID {} does not exist", user_id, school_id)));
            }
            let now = get_time();

            let expiration_ts = self.get_expiration_ts(school_id, None, now, duration_id).await.trace()?;

            let description = "Payment plan".to_string();
            // let expiration_ts = now + 30 *1000;
            let result = self.pay_with_user_method (
                user_id,
                school_id,
                None,
                stripe_payment_method_ids, 
                stripe_customer_id,
                description,
                price,
                now,
                None,
                stripe_client,
                Some(expiration_ts),
                group_members,
                Some(base_payment_plan_id),
                Some(payment_plan_id),
            ).await.trace()?;
            return Ok(result);

        }

        Ok(false)
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
    ) -> AppResult<(bool, Option<Uuid>, Option<Uuid>)>
    {

        match price {
            Some(price) => {
                // Class is Free
                if *price <= BigDecimal::from(0) { 
                    return Ok((true, None, None));
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
                    return Err(AppError::Internal(format!("User with ID {} does not exist", user_id)));
                }

                for row in result.rows().trace()? {
                    let mut expired_active_plans = Vec::new();

                    let (ref_school_id, active_payment_plans, payment_provider, stripe_payment_method_ids, stripe_customer_id): (Uuid, Option<Vec<(Uuid, CqlTimestamp)>>, Option<Uuid>, Option<Vec<String>>, Option<String>) = row.trace()?;
                    if ref_school_id != *school_id {
                        return Err(AppError::Internal(format!("User Id {} has wrong school ID {} class id {} does not exist", user_id, school_id, class_id)));
                    }

                    let now = get_time();
                    let mut has_pass = false;
                    let mut user_payment_plan_id = None;
                    // Check if active pass, also clean up expired passes
                    match active_payment_plans {
                        Some(active_payment_plans) => {
                            for active_payment_plan in active_payment_plans {
                                let (ref_user_payment_plan_id, expiration_ts) = active_payment_plan;
                                let expiration_ts = expiration_ts.0;
                                if now > expiration_ts {
                                    expired_active_plans.push(active_payment_plan);
                                } else {
                                    has_pass = true;
                                    user_payment_plan_id = Some(ref_user_payment_plan_id);
                                } 
                            }
                        },
                        None => {}
                    }



                    // Clean up expired active plans
                    self.remove_expired_payment_plans(user_id, &expired_active_plans);

                    if has_pass {
                        return Ok((true, None, user_payment_plan_id));
                    }
                    
                    
                    // Try individuals payment methods first
                    match stripe_customer_id {
                        Some(stripe_customer_id) => {
                            match stripe_payment_method_ids {
                                Some(stripe_payment_method_ids) => {
                                    for payment_method_id in stripe_payment_method_ids {
                                        let user_payment_id = Uuid::new_v4();
                                        let description = format!("Casual attendance of class:{}", class_id);
                                        let currency = "aud";
                                        // let amount = price*BigDecimal::from(100);
                                        let cents_i64 = (price * BigDecimal::from(100))
                                            .round(0)
                                            .to_i64()
                                            .unwrap();
                                        let result = stripe_client.charge_payment_method(cents_i64, currency, &payment_method_id, &stripe_customer_id, &user_payment_id, school_id, user_id, Some(&description)).await.trace()?;
                                        // result.id
                                        let stripe_payment_id = result.id;
                                        let duration = PaymentPlanDuration::SingleClass as i32;
                                        let payment_status = 1; // captured

                                        let zero_guuid = Uuid::nil();
                                        let now = scylla::value::CqlTimestamp(now);
                                        let class_start_ts = scylla::value::CqlTimestamp(class_start_ts);
                                        
                                        let result = self.session
                                            .query_unpaged("insert into mma.user_payment (user_payment_id, user_id, base_payment_plan_id, class_id, class_start_ts, created_ts, stripe_payment_id, captured_ts, captured, status) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", 
                                            (user_payment_id, user_id, zero_guuid, class_id, class_start_ts, now, stripe_payment_id, now, price, payment_status)) // Pass the query string and bound values
                                            .await.trace()?;
                                        return Ok((true, Some(user_payment_id), None));
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
            None => {return Ok((true, None, None)); }
        }

        // Check if user has paid for the class
        let classes_attended = self.get_user_class_attendance_count(user_id, class_id).await.trace()?;
        if free_lessons <= classes_attended {
            let user_can_pay = self.can_user_pay(user_id).await.trace()?;
            if !user_can_pay {
                return Err(AppError::UserNoCreditCard("".to_string()));
            }
        }

        Ok((false, None, None))
    }


    pub async fn lock_class_attendance (
        &self,
        class_id: &Uuid,
        class_start_ts: i64,
    ) -> AppResult<()> {
        let cql_class_start_ts: CqlTimestamp = scylla::value::CqlTimestamp(class_start_ts);

        let result = self.session
            .query_unpaged(
                "INSERT INTO mma.class_attendance_locks (class_id, class_start_ts) VALUES (?, ?) IF NOT EXISTS",
                (class_id,cql_class_start_ts)
            )
            .await.trace()?
            .into_rows_result().trace()?;
    
        let mut locked = false;
        for row in result.rows().trace()? {
            let (ref_locked, _, _) : (bool, Option<Uuid>, Option<CqlTimestamp>) = row.trace()?;
            locked = ref_locked;
        }


        if !locked {
            return Err(AppError::Internal("Class is locked, try again shortly".to_string()));
        }

        tracing::info!("Locked class_attendance_locks");
        return Ok(());
    }





    /// Thread-safe atomic increment of user count for dashboard stats using generic locking
    /// This function is safe for concurrent operations across multiple threads and nodes
    pub async fn increment_user_count(&self, school_id: &Uuid) -> AppResult<()> {
        let lock_key = format!("user_count:{}", school_id);
        
        // Use generic locking mechanism
        self.acquire_lock(&lock_key).await?;
        
        let result = self.increment_user_count_locked_section(school_id).await;
        
        self.release_lock(&lock_key).await?;
        
        result
    }

    /// Generic lock acquisition using LWT with string-based keys
    /// This can be used for any type of distributed locking across the cluster
    pub async fn acquire_lock(&self, lock_key: &str) -> AppResult<()> {
        let now = get_time();
        let acquired_ts = CqlTimestamp(now);
        
        let result = self.session
            .query_unpaged(
                "INSERT INTO mma.generic_locks (lock_key, acquired_ts) VALUES (?, ?) IF NOT EXISTS",
                (lock_key, acquired_ts)
            )
            .await.trace()?
            .into_rows_result().trace()?;

        let mut locked = false;
        for row in result.rows().trace()? {
            let (ref_locked, _, _): (bool, Option<String>, Option<CqlTimestamp>) = row.trace()?;
            locked = ref_locked;
        }

        if !locked {
            return Err(AppError::Internal(format!("Could not acquire lock: {}", lock_key)));
        }

        tracing::info!("Acquired lock: {}", lock_key);
        Ok(())
    }

    /// Generic lock release
    pub async fn release_lock(&self, lock_key: &str) -> AppResult<()> {
        self.session
            .query_unpaged(
                "DELETE FROM mma.generic_locks WHERE lock_key = ?",
                (lock_key,)
            )
            .await.trace()?;
            
        tracing::info!("Released lock: {}", lock_key);
        Ok(())
    }

    /// Generic lock-execute-unlock pattern
    /// Use this for any operation that needs distributed locking
    /// 
    /// Example usage:
    /// ```rust
    /// let lock_key = format!("resource_type:{}", resource_id);
    /// self.with_lock(&lock_key, || async {
    ///     // Your critical section code here
    ///     Ok(result)
    /// }).await?
    /// ```
    pub async fn with_lock<F, Fut, T>(&self, lock_key: &str, operation: F) -> AppResult<T>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = AppResult<T>>,
    {
        self.acquire_lock(lock_key).await?;
        
        let result = operation().await;
        
        self.release_lock(lock_key).await?;
        
        result
    }

    /// Increment user count in locked section - safe read-modify-write
    pub async fn increment_user_count_locked_section(&self, school_id: &Uuid) -> AppResult<()> {
        let now = get_time();
        
        // Define all the stat combinations we need to increment
        let mut stat_keys = vec![
            // ALL window - no timestamp
            (school_id, school_id, StatIdType::SCHOOL as i8, StatWindow::ALL as i8, StatCountType::TotalMembers as i8, 0i16, 0i16, CqlTimestamp(0)),
        ];
        
        // Add time-windowed stats
        let windows = [StatWindow::WEEK, StatWindow::MONTH, StatWindow::YEAR];
        for window in windows.iter() {
            let truncated_ts = truncate_timestamp(now, *window);
            stat_keys.push((
                school_id, 
                school_id, 
                StatIdType::SCHOOL as i8, 
                *window as i8, 
                StatCountType::TotalMembers as i8, 
                0i16, 
                0i16, 
                CqlTimestamp(truncated_ts)
            ));
        }
        
        // For each stat, read current value, increment, and write back
        for (school_id_param, id, id_type, window, count_type, v1, v2, ts) in stat_keys {
            // Read current count
            let result = self.session
                .query_unpaged(
                    "SELECT count FROM mma.dash_stats WHERE school_id = ? AND id = ? AND id_type = ? AND window = ? AND count_type = ? AND v1 = ? AND v2 = ? AND ts = ?",
                    (school_id_param, id, id_type, window, count_type, v1, v2, ts)
                )
                .await.trace()?
                .into_rows_result().trace()?;

            let current_count = if result.rows_num() > 0 {
                let mut count = 0;
                for row in result.rows().trace()? {
                    let (existing_count,): (i32,) = row.trace()?;
                    count = existing_count;
                    break;
                }
                count
            } else {
                0
            };

            let new_count = current_count + 1;
            
            // Insert or update with new count
            self.session
                .query_unpaged(
                    "INSERT INTO mma.dash_stats (school_id, id, id_type, window, count, count_type, v1, v2, ts) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (school_id_param, id, id_type, window, new_count, count_type, v1, v2, ts)
                )
                .await.trace()?;
        }
        
        tracing::info!("Incremented user count for school: {}", school_id);
        Ok(())
    }

    // CREATE TABLE IF NOT EXISTS {}.dash_stats { school_id uuid, id uuid, id_type tinyint, window tinyint, count int, count_type tinyint }; 
    pub async fn update_dashboard_stats (
        &self,
        school_id: &Uuid,
    ) -> AppResult<()> {
        // TODO - Need to handle for performing this task multiple times especially in regards to deleted information. As overridden data kind of works but in the case of non overridden data will linger.

        let mut user_hashmap = HashMap::new();
        let mut class_hashmap = HashMap::new();
        // class (school_id uuid, class_id uuid, venue_id uuid
        // Get classes for school
        let class_rows = self.session
            .query_unpaged(
                "SELECT class_id, venue_id FROM mma.class WHERE school_id = ?",
                (school_id,)
            )
            .await.trace()?
            .into_rows_result().trace()?;

        // Early return if empty
        if class_rows.rows_num() == 0 {
            return Ok(());
        }        

        let mut school_class_ids = Vec::new();
        for row in class_rows.rows().trace()? {
            let (class_id, venue_id): (Uuid, Uuid) = row.trace()?;
            class_hashmap.insert(class_id, (venue_id, ));
            school_class_ids.push(class_id);
        }


        // Step 1: Get attendance records
        let attendance_rows = self.session
            .query_unpaged(
                "SELECT class_id, user_id, class_start_ts, is_instructor FROM mma.attendance WHERE class_id in ?",
                (school_class_ids,)
            )
            .await.trace()?
            .into_rows_result().trace()?;

        // Early return if empty
        if attendance_rows.rows_num() == 0 {
            return Ok(());
        }

        // let mut attendance_data = Vec::new();

        let mut count_total = HashMap::new();

        // Step 2: Enrich attendance with user info
        for row in attendance_rows.rows().trace()? {
            let (class_id, user_id, cql_class_start_ts, is_instructor): (Uuid, Uuid, CqlTimestamp, bool) = row.trace()?;
            if !user_hashmap.contains_key(&user_id) {
                // Lookup user details
                let user_row = self.session
                    .query_unpaged(
                        "SELECT gender, dob FROM mma.user WHERE user_id = ?",
                        (user_id,)
                    )
                    .await.trace()?
                    .into_rows_result().trace()?;

                for user_data in user_row.rows().trace()? {
                    let (gender, dob): (Option<String>, Option<chrono::NaiveDate>) = user_data?;
                    let gender_id = match gender.as_deref() {
                        Some("male") => Some(StatGender::Male),
                        Some("female") => Some(StatGender::Female),
                        Some(_) => None, // or Some(StatGender::Unknown) if you define it
                        None => None,
                    };

                    let age = get_naive_age(&dob);
                    user_hashmap.insert(user_id, (gender_id, age));

                    break;
                }
            }
            let user_d = user_hashmap.get(&user_id);
            let user_d = match user_d {
                Some((gender_id, age)) => {

                    // attendance_data.push((class_id, user_id, cql_class_start_ts.0, is_instructor, gender, age));

                    // Class Stats all
                    *count_total.entry((class_id, StatIdType::CLASS as i8, StatWindow::ALL as i8, StatCountType::AttendanceAll as i8, 0, 0 as i16, 0)).or_insert(0) += 1;

                    let trunc_ts = truncate_timestamp(cql_class_start_ts.0, StatWindow::HOUR);
                    *count_total.entry((class_id, StatIdType::CLASS as i8, StatWindow::HOUR as i8, StatCountType::AttendanceAll as i8, 0, 0, trunc_ts)).or_insert(0) += 1;

                    let trunc_ts = truncate_timestamp(cql_class_start_ts.0, StatWindow::DAY);
                    *count_total.entry((class_id, StatIdType::CLASS as i8, StatWindow::DAY as i8, StatCountType::AttendanceAll as i8, 0, 0, trunc_ts)).or_insert(0) += 1;

                    let trunc_ts = truncate_timestamp(cql_class_start_ts.0, StatWindow::WEEK);
                    *count_total.entry((class_id, StatIdType::CLASS as i8, StatWindow::WEEK as i8, StatCountType::AttendanceAll as i8, 0, 0, trunc_ts)).or_insert(0) += 1;

                    let trunc_ts = truncate_timestamp(cql_class_start_ts.0, StatWindow::MONTH);
                    *count_total.entry((class_id, StatIdType::CLASS as i8, StatWindow::MONTH as i8, StatCountType::AttendanceAll as i8, 0, 0, trunc_ts)).or_insert(0) += 1;

                    let trunc_ts = truncate_timestamp(cql_class_start_ts.0, StatWindow::YEAR);
                    *count_total.entry((class_id, StatIdType::CLASS as i8, StatWindow::YEAR as i8, StatCountType::AttendanceAll as i8, 0, 0, trunc_ts)).or_insert(0) += 1;


                    if *gender_id == Some(StatGender::Male) {
                        *count_total.entry((class_id, StatIdType::CLASS as i8, StatWindow::ALL as i8, StatCountType::AttendanceGender as i8, StatGender::Male as i16, 0, trunc_ts)).or_insert(0) += 1;

                        let trunc_ts = truncate_timestamp(cql_class_start_ts.0, StatWindow::HOUR);
                        *count_total.entry((class_id, StatIdType::CLASS as i8, StatWindow::HOUR as i8, StatCountType::AttendanceGender as i8, StatGender::Male as i16, 0, trunc_ts)).or_insert(0) += 1;

                        let trunc_ts = truncate_timestamp(cql_class_start_ts.0, StatWindow::DAY);
                        *count_total.entry((class_id, StatIdType::CLASS as i8, StatWindow::DAY as i8, StatCountType::AttendanceGender as i8, StatGender::Male as i16, 0, trunc_ts)).or_insert(0) += 1;

                        let trunc_ts = truncate_timestamp(cql_class_start_ts.0, StatWindow::WEEK);
                        *count_total.entry((class_id, StatIdType::CLASS as i8, StatWindow::WEEK as i8, StatCountType::AttendanceGender as i8, StatGender::Male as i16, 0, trunc_ts)).or_insert(0) += 1;

                        let trunc_ts = truncate_timestamp(cql_class_start_ts.0, StatWindow::MONTH);
                        *count_total.entry((class_id, StatIdType::CLASS as i8, StatWindow::MONTH as i8, StatCountType::AttendanceGender as i8, StatGender::Male as i16, 0, trunc_ts)).or_insert(0) += 1;

                        let trunc_ts = truncate_timestamp(cql_class_start_ts.0, StatWindow::YEAR);
                        *count_total.entry((class_id, StatIdType::CLASS as i8, StatWindow::YEAR as i8, StatCountType::AttendanceGender as i8, StatGender::Male as i16, 0, trunc_ts)).or_insert(0) += 1;
                    }

                    if *gender_id == Some(StatGender::Female) {
                        *count_total.entry((class_id, StatIdType::CLASS as i8, StatWindow::ALL as i8, StatCountType::AttendanceGender as i8, StatGender::Female as i16, 0, trunc_ts)).or_insert(0) += 1;

                        let trunc_ts = truncate_timestamp(cql_class_start_ts.0, StatWindow::HOUR);
                        *count_total.entry((class_id, StatIdType::CLASS as i8, StatWindow::HOUR as i8, StatCountType::AttendanceGender as i8, StatGender::Female as i16, 0, trunc_ts)).or_insert(0) += 1;

                        let trunc_ts = truncate_timestamp(cql_class_start_ts.0, StatWindow::DAY);
                        *count_total.entry((class_id, StatIdType::CLASS as i8, StatWindow::DAY as i8, StatCountType::AttendanceGender as i8, StatGender::Female as i16, 0, trunc_ts)).or_insert(0) += 1;

                        let trunc_ts = truncate_timestamp(cql_class_start_ts.0, StatWindow::WEEK);
                        *count_total.entry((class_id, StatIdType::CLASS as i8, StatWindow::WEEK as i8, StatCountType::AttendanceGender as i8, StatGender::Female as i16, 0, trunc_ts)).or_insert(0) += 1;

                        let trunc_ts = truncate_timestamp(cql_class_start_ts.0, StatWindow::MONTH);
                        *count_total.entry((class_id, StatIdType::CLASS as i8, StatWindow::MONTH as i8, StatCountType::AttendanceGender as i8, StatGender::Female as i16, 0, trunc_ts)).or_insert(0) += 1;

                        let trunc_ts = truncate_timestamp(cql_class_start_ts.0, StatWindow::YEAR);
                        *count_total.entry((class_id, StatIdType::CLASS as i8, StatWindow::YEAR as i8, StatCountType::AttendanceGender as i8, StatGender::Female as i16, 0, trunc_ts)).or_insert(0) += 1;
                    }


                    // School Stats all
                    *count_total.entry((*school_id, StatIdType::SCHOOL as i8, StatWindow::ALL as i8, StatCountType::AttendanceAll as i8, 0, 0, trunc_ts)).or_insert(0) += 1;

                    let trunc_ts = truncate_timestamp(cql_class_start_ts.0, StatWindow::HOUR);
                    *count_total.entry((*school_id, StatIdType::SCHOOL as i8, StatWindow::HOUR as i8, StatCountType::AttendanceAll as i8, 0, 0, trunc_ts)).or_insert(0) += 1;

                    let trunc_ts = truncate_timestamp(cql_class_start_ts.0, StatWindow::DAY);
                    *count_total.entry((*school_id, StatIdType::SCHOOL as i8, StatWindow::DAY as i8, StatCountType::AttendanceAll as i8, 0, 0, trunc_ts)).or_insert(0) += 1;

                    let trunc_ts = truncate_timestamp(cql_class_start_ts.0, StatWindow::WEEK);
                    *count_total.entry((*school_id, StatIdType::SCHOOL as i8, StatWindow::WEEK as i8, StatCountType::AttendanceAll as i8, 0, 0, trunc_ts)).or_insert(0) += 1;

                    let trunc_ts = truncate_timestamp(cql_class_start_ts.0, StatWindow::MONTH);
                    *count_total.entry((*school_id, StatIdType::SCHOOL as i8, StatWindow::MONTH as i8, StatCountType::AttendanceAll as i8, 0, 0, trunc_ts)).or_insert(0) += 1;

                    let trunc_ts = truncate_timestamp(cql_class_start_ts.0, StatWindow::YEAR);
                    *count_total.entry((*school_id, StatIdType::SCHOOL as i8, StatWindow::YEAR as i8, StatCountType::AttendanceAll as i8, 0, 0, trunc_ts)).or_insert(0) += 1;


                }
                None => {}
            };

        }


        // Step 4: Insert results into dash_stats
        for ((id, id_type, stat_window, stat_count_type, v1, v2, ts), count) in count_total {
            println!("Inserting stat: id: {}, id_type: {}, window: {}, count_type: {}, v1: {}, v2: {}, ts: {}, count: {}", 
                id, id_type, stat_window, stat_count_type, v1, v2, ts, count);
            self.session
                .query_unpaged(
                    "insert into mma.dash_stats (school_id, id, id_type, window, count, count_type, v1, v2, ts)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        school_id, 
                        id, 
                        id_type,
                        stat_window, // Assume daily rollup for now
                        count,
                        stat_count_type,
                        v1,
                        v2,
                        CqlTimestamp(ts)
                    )
                )
                .await?;
        }

        Ok(())
    }


    pub async fn get_dash_stats (
        &self,
        school_id: &Uuid,
    ) -> AppResult<Vec<DashStat>> { 
        let result = self.session
            .query_unpaged(
                "SELECT id, id_type, window, count, count_type, v1, v2, ts FROM mma.dash_stats WHERE school_id = ?",
                (school_id,)
            )
            .await.trace()?
            .into_rows_result().trace()?;

        let mut results = Vec::new();
        for row in result.rows().trace()? {
            let (id, id_type, window, count, count_type, v1, v2, ts): (Uuid, i8, i8, i32, i8, i16, i16, CqlTimestamp) = row.trace()?;
            results.push(DashStat{
                id,
                id_type,
                window,
                count,
                count_type,
                v1,
                v2,
                ts: ts.0,
            });
        }
        
        return Ok(results);
    }


    pub async fn unlock_class_attendance (
        &self,
        class_id: &Uuid,
        class_start_ts: i64,
    ) -> AppResult<()> {
        let cql_class_start_ts: CqlTimestamp = scylla::value::CqlTimestamp(class_start_ts);

        let unlocked = self.session
            .query_unpaged(
                "delete from mma.class_attendance_locks  where class_id = ? and class_start_ts = ?",
                (class_id,cql_class_start_ts)
            )
            .await.trace()?;
        tracing::info!("UnLocked class_attendance_locks");

        return Ok(());
    }

    pub async fn set_class_attendance_locked_section (
        &self,
        class_id: &Uuid,
        school_id: &Uuid,
        user_id: &Uuid,
        waiver_id: &Option<Uuid>,
        price: &Option<BigDecimal>,
        free_lessons: &Option<i32>,
        present: bool,
        class_start_ts: i64,
        stripe_client: &StripeClient
    ) -> AppResult<bool> {
        let mut user_payment_id = None;
        let mut user_payment_plan_id = None;
        let cql_class_start_ts = scylla::value::CqlTimestamp(class_start_ts); 


        let result = self.session
            .query_unpaged("SELECT user_id FROM mma.attendance where class_id = ? and class_start_ts = ? and user_id = ?",
            (class_id, cql_class_start_ts, user_id)) // Pass the query string and bound values
            .await.trace()?
            .into_rows_result().trace()?;
    
        // Requesting to add a student who has already been added
        if result.rows_num() == 1 && present {
            return Ok(true);
        }

        // Requesting removal of student that was already removed
        if result.rows_num() == 0 && !present {
            return Ok(true);
        }

        let result = self.session
            .query_unpaged("SELECT count FROM mma.class_attendance_count where class_id = ? and class_start_ts = ?",
            (class_id, cql_class_start_ts)) // Pass the query string and bound values
            .await.trace()?
            .into_rows_result().trace()?;

        let mut class_attendance_count = 0;
        for row in result.rows().trace()? {
            let (count, ): (i32, ) = row.trace()?;
            class_attendance_count = count;
        }



        match waiver_id {
            Some(id) => {
                if present {
                    // Check if user has accepted the waiver
                    let accepted = self.has_user_accepted_waiver(user_id, &id).await.trace()?;
                    if !accepted {
                        return Err(AppError::UserWaiverNotAccepted(format!("")));
                    }
                }
            },
            None => {}
        }

        if price.is_some() {
            let free_lessons = free_lessons.unwrap_or(0);
            // If the class has a price
            if present {
                let (paid, ref_user_payment_id, ref_user_payment_plan_id) = self.pay_class(user_id, school_id, class_id, class_start_ts, stripe_client, free_lessons, &price).await.trace()?;
                user_payment_id = ref_user_payment_id;
                user_payment_plan_id = ref_user_payment_plan_id;
                if !paid { 
                    return Ok(false);
                }

            }
        }

        // Get current timestamp
        let now = get_time();
        let now = scylla::value::CqlTimestamp(now);

        // Prepare the statement once
        let prepared = match present {
            true => {
                self
                    .session
                    .prepare(
                        "INSERT INTO mma.attendance (class_id, user_id, class_start_ts, is_instructor, checkin_ts, user_payment_id, user_payment_plan_id) VALUES (?, ?, ?, ?, ?, ?, ?)"
                    )
                    .await.trace()?
            },
            false => {
                self
                    .session
                    .prepare(
                        "DELETE FROM mma.attendance WHERE class_id = ? AND class_start_ts = ? and user_id = ?"
                    )
                    .await.trace()?
            }
        };

        

        let prepared_count = self
            .session
            .prepare(
                "INSERT INTO mma.attendance_count (class_id, user_id, count) VALUES (?, ?, ?)"
            )
            .await.trace()?;

        let prepared_class_count = self
            .session
            .prepare(
                "INSERT INTO mma.class_attendance_count (class_id, class_start_ts, count) VALUES (?, ?, ?)"
            )
            .await.trace()?;


        // Create batch
        let mut batch = scylla::statement::batch::Batch::default();
        // Add each user_id as a separate statement in the batch if present
        batch.append_statement(prepared);
        batch.append_statement(prepared_count);
        batch.append_statement(prepared_class_count);

        let attendance_count = self.get_user_class_attendance_count(user_id, class_id).await.trace()?;

        let batch_value = match present {
            true => {
                let values = ((class_id, user_id, cql_class_start_ts, false, now, user_payment_id, user_payment_plan_id),
                 (class_id, user_id, attendance_count+1),
                 (class_id, cql_class_start_ts, class_attendance_count+1));
                 tracing::info!("Adding to class attendance {}", attendance_count);
                self.session.batch(&batch, &values).await.trace()?;

            },
            false => {
                let values = ((class_id, cql_class_start_ts, user_id),
                    (class_id, user_id,attendance_count-1),
                    (class_id, cql_class_start_ts, class_attendance_count-1));
                tracing::info!("Removing to class attendance {}", attendance_count);

                self.session.batch(&batch, &values).await.trace()?;
            }
        };
        
        // Execute batch


        return Ok(true);
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

        if user_ids.len() != 1 {
            return Err(AppError::Internal("Only supports adding 1 student at a time".to_string()));
        }
        let modify_user_id = user_ids.get(0).unwrap();
        let is_present = *present.get(0).unwrap();
        let cql_class_start_ts: CqlTimestamp = scylla::value::CqlTimestamp(class_start_ts);


        // mma.attendance (class_id, user_id, class_start_ts, is_instructor, checkin_ts, user_payment_id, user_payment_plan_id) VALUES (?, ?, ?, ?, ?, ?, ?)

        let result = self.session
            .query_unpaged("SELECT user_id FROM mma.attendance where class_id = ? and class_start_ts = ? and user_id = ?",
            (class_id, cql_class_start_ts, modify_user_id)) // Pass the query string and bound values
            .await.trace()?
            .into_rows_result().trace()?;
    
        // Requesting to add a student who has already been added
        if result.rows_num() == 1 && is_present {
            return Ok(true);
        }

        // Requesting removal of student that was already removed
        if result.rows_num() == 0 && !is_present {
            return Ok(true);
        }


        let adding_student_count = present.iter().filter(|&&p| p).count();
        let remove_student_count = present.iter().filter(|&&p| !p).count();
        let total_student_attend_dif = adding_student_count as i32 - remove_student_count as i32;


        let class_valid_ts = self.is_valid_class_start(&class_id, &school_id, class_start_ts, Some(total_student_attend_dif)).await.trace()?;
        
        if !class_valid_ts {
            return Err(AppError::Internal("Invalid class start timestamp".to_string()));
        }

        let result = self.session
            .query_unpaged("SELECT waiver_id, price, free_lessons FROM mma.class where class_id = ? and school_id = ?", 
            (class_id, school_id)) // Pass the query string and bound values
            .await.trace()?
            .into_rows_result().trace()?;
        
        if result.rows_num() == 0 {
            return Err(AppError::Internal(format!("Class with ID {} does not exist", class_id)));
        }

        for row in result.rows().trace()? {
            let (waiver_id, price, free_lessons): (Option<Uuid>, Option<BigDecimal>, Option<i32>) = row.trace()?;
        
            self.lock_class_attendance(class_id, class_start_ts).await.trace()?;
            
            let result = self.set_class_attendance_locked_section(class_id, school_id, modify_user_id, &waiver_id, &price, &free_lessons, is_present, class_start_ts, stripe_client).await.trace();
        
            self.unlock_class_attendance(class_id, class_start_ts).await.trace()?;
            result?;

            break;
        }

        // let school_id = *school_id;

        // task::spawn(async move {
        let start = std::time::Instant::now();

        // TODO - perform this as a seperate background task
        if let Err(e) = self.update_dashboard_stats(&school_id).await {
            tracing::error!("Failed to update dashboard stats: {:?}", e);
        } else {
            tracing::info!("Dashboard stats updated in {:?}", start.elapsed());
        }
        // });

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
        let now = get_time();
        let now_cql = scylla::value::CqlTimestamp(now);
        

        let result = self.session
            .query_unpaged(
                "SELECT deleted_ts, timezone, capacity FROM mma.class WHERE class_id = ? and school_id = ?",
                (class_id, school_id),
            )
            .await.trace()?
            .into_rows_result().trace()?;   

        // Check if the class exists and is not deleted
        if result.rows_num() == 0 {
            println!("Class with ID {} does not exist", class_id);
            return Ok(false);
        }
        let mut timezone = String::new();
        for row in result.rows().trace()? {
            let (deleted_ts, db_timezone, capacity): (CqlTimestamp, String, Option<i32>) = row.trace()?;
            
            // Check if the class is deleted
            if deleted_ts != CqlTimestamp(0) {
                println!("Class with ID {} is deleted", class_id);
                return Ok(false);
            }
            
            // Check if the class belongs to the correct school
            // if class_school_id != *school_id {
            //     println!("Class with ID {} does not belong to school {}", class_id, school_id);
            //     return Ok(false);
            // }
            
            timezone = db_timezone;
            match capacity {
                Some(capacity) => {

                    match student_attend_dif {
                        Some(dif) => {
                            if dif > 0 {
                                let result = self.session
                                    .query_unpaged(
                                        "SELECT count FROM mma.class_attendance_count WHERE class_id = ? and class_start_ts = ?",
                                        (class_id, query_class_start_ts_cql),
                                    )
                                    .await.trace()?
                                    .into_rows_result().trace()?;


                                let mut student_attend_count: i32 = 0;
                                for row in result.rows().trace()? {
                                    let (count,): (i32,) = row.trace()?;
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
            .await.trace()?
            .into_rows_result().trace()?;
            
        if result.rows_num() == 0 {
            println!("Class with ID {} does not exist", class_id);
            return Ok(false);
        }
        
        // Check if the class is valid based on frequency rules
        for row in result.rows().trace()? {
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


    pub async fn get_school_title(
        &self,
        school_id: &Uuid,
    ) -> AppResult<String> {
        let result = self.session
            .query_unpaged(
                "SELECT title FROM mma.school WHERE school_id = ?",
                (school_id,),
            )
            .await.trace()?
            .into_rows_result().trace()?;

        for row in result.rows().trace()? {
            let (title, ): (Option<String>, ) = row.trace()?;
            match title {
                Some(title) => return Ok(title),
                None => return Ok("".to_string())
            };
        }
           
        return Err(AppError::BadRequest("Could not find school".to_string()));
    }

    pub async fn get_school_users(
        &self,
        school_id: &Uuid,
    ) -> AppResult<Vec<SchoolUser>> {
        let mut users: Vec<SchoolUser> = Vec::new();

        let result = self.session
            .query_unpaged(
                "SELECT user_id, first_name, surname, email, email_verified, photo_id FROM mma.user WHERE school_id = ?",
                (school_id,),
            )
            .await.trace()?
            .into_rows_result().trace()?;

        for row in result.rows().trace()? {
            let (user_id, first_name, surname, email, email_verified, img): (Uuid, String, String, Option<String>, Option<bool>, Option<String>) = row.trace()?;
            let email_verified = match email_verified {
                Some(email_verified) => email_verified,
                None => false
            };

            users.push(SchoolUser{
                user_id,
                first_name,
                surname,
                email,
                email_verified,
                img
            });
        }
        return Ok(users); 
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
            .await.trace()?
            .into_rows_result().trace()?;

        // println!("Attendance query result: {:?}", result);
        let mut attending_students: Vec<Uuid> = Vec::new();
        for row in result.rows().trace()?
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
            .await.trace()?
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

    pub async fn get_class_history(
        &self,
        class_id: &Uuid,
        school_id: &Uuid,
        from_date: Option<&str>,
        to_date: Option<&str>,
    ) -> AppResult<(Vec<ClassHistoryRecord>, ClassHistoryStats)> {
        use chrono::{TimeZone, NaiveDate, NaiveTime};
        use chrono_tz::Australia::Sydney;

        // Parse date filters if provided - use Sydney timezone
        let from_ts = if let Some(from_str) = from_date {
            let naive_date = NaiveDate::parse_from_str(from_str, "%Y-%m-%d")
                .map_err(|_| AppError::Internal("Invalid from_date format".to_string()))?;
            let naive_datetime = naive_date.and_time(NaiveTime::from_hms_opt(0, 0, 0).unwrap());
            let sydney_datetime = Sydney.from_local_datetime(&naive_datetime).single()
                .ok_or_else(|| AppError::Internal("Invalid Sydney timezone conversion".to_string()))?;
            Some(CqlTimestamp(sydney_datetime.timestamp_millis()))
        } else {
            None
        };

        let to_ts = if let Some(to_str) = to_date {
            let naive_date = NaiveDate::parse_from_str(to_str, "%Y-%m-%d")
                .map_err(|_| AppError::Internal("Invalid to_date format".to_string()))?;
            let naive_datetime = naive_date.and_time(NaiveTime::from_hms_opt(23, 59, 59).unwrap());
            let sydney_datetime = Sydney.from_local_datetime(&naive_datetime).single()
                .ok_or_else(|| AppError::Internal("Invalid Sydney timezone conversion".to_string()))?;
            Some(CqlTimestamp(sydney_datetime.timestamp_millis()))
        } else {
            None
        };

        // First get attendance records with date filters
        let attendance_result = match (from_ts, to_ts) {
            (Some(from), Some(to)) => {
                self.session
                    .query_unpaged(
                        "SELECT user_id, class_start_ts, checkin_ts, user_payment_id, user_payment_plan_id 
                         FROM mma.attendance 
                         WHERE class_id = ? AND class_start_ts >= ? AND class_start_ts <= ?",
                        (class_id, from, to)
                    )
                    .await.trace()?
                    .into_rows_result().trace()?
            },
            (Some(from), None) => {
                self.session
                    .query_unpaged(
                        "SELECT user_id, class_start_ts, checkin_ts, user_payment_id, user_payment_plan_id 
                         FROM mma.attendance 
                         WHERE class_id = ? AND class_start_ts >= ?",
                        (class_id, from)
                    )
                    .await.trace()?
                    .into_rows_result().trace()?
            },
            (None, Some(to)) => {
                self.session
                    .query_unpaged(
                        "SELECT user_id, class_start_ts, checkin_ts, user_payment_id, user_payment_plan_id 
                         FROM mma.attendance 
                         WHERE class_id = ? AND class_start_ts <= ?",
                        (class_id, to)
                    )
                    .await.trace()?
                    .into_rows_result().trace()?
            },
            (None, None) => {
                self.session
                    .query_unpaged(
                        "SELECT user_id, class_start_ts, checkin_ts, user_payment_id, user_payment_plan_id 
                         FROM mma.attendance 
                         WHERE class_id = ?",
                        (class_id,)
                    )
                    .await.trace()?
                    .into_rows_result().trace()?
            },
        };

        // Get user information for the school
        let user_result = self.session
            .query_unpaged(
                "SELECT user_id, first_name, surname, email FROM mma.user WHERE school_id = ?",
                (school_id,)
            )
            .await.trace()?
            .into_rows_result().trace()?;

        // Build user lookup map
        let mut user_map = std::collections::HashMap::new();
        for row in user_result.rows().trace()? {
            let (user_id, first_name, surname, email): (Uuid, String, String, Option<String>) = row.trace()?;
            user_map.insert(user_id, (first_name, surname, email));
        }

        let mut history_records = Vec::new();
        let mut unique_sessions = std::collections::HashSet::new();
        let mut total_revenue = 0.0;

        for row in attendance_result.rows().trace()? {
            let (user_id, class_start_ts, checkin_ts, user_payment_id, user_payment_plan_id): 
                (Uuid, CqlTimestamp, CqlTimestamp, Option<Uuid>, Option<Uuid>) = row.trace()?;

            // Get user information from the map
            let (first_name, surname, email) = match user_map.get(&user_id) {
                Some((fname, sname, email)) => (fname.clone(), sname.clone(), email.clone()),
                None => continue, // Skip if user not found in this school
            };

            // Add session to unique set for stats (using timestamp as key)
            unique_sessions.insert(class_start_ts.0);

            // Get payment information if available
            let (payment_info, amount_paid, payment_status) = if let Some(payment_id) = user_payment_id {
                self.get_payment_details(payment_id).await.unwrap_or((None, 0.0, 2))
            } else if user_payment_plan_id.is_some() {
                (Some(PaymentInfo { type_name: "pass".to_string(), last4: None }), 0.0, 2) // Free with pass
            } else {
                (None, 0.0, 2) // Free
            };

            total_revenue += amount_paid;

            history_records.push(ClassHistoryRecord {
                user_id,
                student_name: format!("{} {}", first_name, surname),
                student_email: email,
                class_start_ts: class_start_ts.0,
                checkin_ts: checkin_ts.0,
                payment_info,
                amount_paid,
                payment_status,
            });
        }

        // Calculate statistics
        let total_sessions = unique_sessions.len() as u32;
        let total_attendees = history_records.len() as u32;
        let avg_attendance = if total_sessions == 0 { 
            0.0 
        } else { 
            total_attendees as f64 / total_sessions as f64
        };

        let stats = ClassHistoryStats {
            total_sessions,
            total_attendees,
            total_revenue,
            avg_attendance,
        };

        tracing::info!(
            "Class {} history stats: sessions={}, attendees={}, revenue={:.2}, avg={:.1}",
            class_id, total_sessions, total_attendees, total_revenue, avg_attendance
        );

        Ok((history_records, stats))
    }

    // Helper function to get payment details
    async fn get_payment_details(&self, payment_id: Uuid) -> AppResult<(Option<PaymentInfo>, f64, i32)> {
        let result = self.session
            .query_unpaged(
                "SELECT captured, status, stripe_payment_id FROM mma.user_payment WHERE user_payment_id = ?",
                (payment_id,)
            )
            .await.trace()?
            .into_rows_result().trace()?;

        for row in result.rows().trace()? {
            let (captured, status, stripe_payment_id): (Option<BigDecimal>, i32, Option<String>) = row.trace()?;
            
            let amount = captured.map(|c| c.to_f64().unwrap_or(0.0)).unwrap_or(0.0);
            let payment_info = stripe_payment_id.map(|_| PaymentInfo {
                type_name: "card".to_string(),
                last4: Some("****".to_string()), // Could extract actual last4 if needed
            });
            
            return Ok((payment_info, amount, status));
        }

        Ok((None, 0.0, 0)) // Default values if payment not found
    }

    pub async fn remove_expired_payment_plans(
        &self,
        user_id: &Uuid,
        expired_active_plans: &Vec<(Uuid, CqlTimestamp)>,
    ) -> AppResult<()> {

        if expired_active_plans.len() == 0 {
            return Ok(());
        }

        tracing::info!("expiring active_payment_plan");
        let result: QueryResult = self.session
            .query_unpaged("update mma.user set active_payment_plans = active_payment_plans - ? where user_id = ?", 
            (expired_active_plans, user_id)) // Pass the query string and bound values
            .await.trace()?;

        Ok(())
    }


    pub async fn get_user_active_payment_plans(
        &self,
        user_id: &Uuid,
        school_id: &Uuid,
    ) -> AppResult<Vec<ActivePaymentPlanData>> {
        let result = self.session
            .query_unpaged(
                "SELECT user_payment_plan_id, base_payment_plan_id, payment_plan_id, group_user_ids, next_group_user_ids, expiration_ts, subscribed from mma.user_payment_plan where user_id = ?;",
                (user_id,),
            )
            .await.trace()?
            .into_rows_result().trace()?;


        let mut user_payment_plans = Vec::new();
        let mut payment_plan_ids = Vec::new();
        let mut base_payment_plan_ids = Vec::new();
        let mut user_ids = Vec::new();
        let now = get_time();
        let mut expired_payment_plan_ids = Vec::new();
        for row in result.rows().trace()? {
            let (user_payment_plan_id, base_payment_plan_id, payment_plan_id, group_user_ids, next_group_user_ids, expiration_ts, subscribed) : (Uuid, Uuid, Uuid, Vec<Uuid>, Vec<Uuid>, CqlTimestamp, bool) = row.trace()?;
            if expiration_ts.0 > now {
                for user in group_user_ids.clone() {
                    if !user_ids.contains(&user) {
                        user_ids.push(user);
                    }
                }

                user_payment_plans.push(UserPaymentPlan{
                    user_payment_plan_id,
                    base_payment_plan_id,
                    payment_plan_id,
                    group_user_ids: group_user_ids,
                    next_group_user_ids,
                    expiration_ts: expiration_ts.0,
                    subscribed
                });


                payment_plan_ids.push(payment_plan_id);
                base_payment_plan_ids.push(base_payment_plan_id);
            } else {
                expired_payment_plan_ids.push((user_payment_plan_id, expiration_ts));
            }
        }

        self.remove_expired_payment_plans(user_id, &expired_payment_plan_ids);

        let mut user_data = HashMap::new();
        let result = self.session
            .query_unpaged(
                "SELECT school_id, user_id, first_name, surname FROM mma.user where user_id in ?;",
                (user_ids,),
            )
            .await.trace()?
            .into_rows_result().trace()?;
        
        for row in result.rows().trace()? {
            let (ref_school_id, ref_user_id, first_name, surname) : (Uuid, Uuid, String, String) = row.trace()?;
            if *school_id != ref_school_id {
                tracing::error!("Error payment plan included user from a different school. This should not be possible. Violation. user_id:{} ref_user_id:{} ref_school_id:{} school_id:{}", user_id, ref_user_id, ref_school_id, school_id);
                continue;
            }
            user_data.insert(ref_user_id, (first_name, surname));
        }
            

        let result = self.session
            .query_unpaged(
                "SELECT payment_plan_id, base_payment_plan_id, grouping_id, min_age, max_age, working, title, description, cost, duration_id FROM mma.payment_plan where school_id = ? and base_payment_plan_id in ? and payment_plan_id in ?;",
                (school_id, base_payment_plan_ids, payment_plan_ids),
            )
            .await.trace()?
            .into_rows_result().trace()?;

        let mut plans: Vec<ActivePaymentPlanData> = Vec::new();
        let mut plan_mapping = HashMap::new();
        for row in result.rows::<PaymentPlanData>().trace()? {
            let plan = row.trace()?;
            plan_mapping.insert(plan.payment_plan_id, plan);
        }




        for user_payment_plan in user_payment_plans {
            let payment_plan = plan_mapping.get(&user_payment_plan.payment_plan_id);
            match payment_plan {
                None => {
                    tracing::error!("db user_payment_plan:{} has no data for specific payment_plan_id:{}", user_payment_plan.user_payment_plan_id, user_payment_plan.payment_plan_id);
                },
                Some(payment_plan) => {
                    let mut members = Vec::new();
                    let mut next_members = Vec::new();
                    for member in user_payment_plan.group_user_ids {
                        let user = user_data.get(&member);
                        match user {
                            Some((first_name, surname)) => {
                                members.push(UserWithName{
                                    user_id: member,
                                    first_name: first_name.clone(),
                                    surname: surname.clone()
                                });
                            },
                            None => {
                                tracing::error!("No user found for group user_id:{} of user_payment_plan_id:{}", member, user_payment_plan.user_payment_plan_id);
                            }
                        }
                    }

                    for member in user_payment_plan.next_group_user_ids {
                        let user = user_data.get(&member);
                        match user {
                            Some((first_name, surname)) => {
                                members.push(UserWithName{
                                    user_id: member,
                                    first_name: first_name.clone(),
                                    surname: surname.clone()
                                });
                            },
                            None => {
                                tracing::error!("No user found for next_group_user_ids user_id:{} of user_payment_plan_id:{}", member, user_payment_plan.user_payment_plan_id);
                            }
                        }
                    }


                    let new_plan = ActivePaymentPlanData {
                        user_payment_plan_id: user_payment_plan.user_payment_plan_id,
                        payment_plan_id: user_payment_plan.payment_plan_id,
                        base_payment_plan_id: user_payment_plan.base_payment_plan_id,
                        grouping_id: payment_plan.grouping_id,
                        min_age: payment_plan.min_age,
                        max_age: payment_plan.max_age,
                        working: payment_plan.working,
                        title: payment_plan.title.clone(),
                        description: payment_plan.description.clone(),
                        cost: payment_plan.cost.clone(),
                        duration_id: payment_plan.duration_id,
                        expiration_ts: user_payment_plan.expiration_ts,
                        subscribed: user_payment_plan.subscribed,
                        members: members,
                        next_members: next_members
                    };
                    plans.push(new_plan);
                }
            }
        }

        return Ok(plans);
    }


    pub async fn update_payment_plan(
        &self,
        school_id: &Uuid,
        plan: &SchoolUpdatePaymentPlanRequest
    ) -> AppResult<()> {

        let plan_id = Uuid::new_v4();

        let base_plan_id = match plan.base_payment_plan_id {
            Some(id) => {
                id
            },
            None => {
                Uuid::new_v4()
            } 
        };

        if plan.duration_id < 0 || plan.duration_id >= PaymentPlanDuration::END as i32 {
            tracing::warn!("Invalid duration id in update_payment_plan");
            return Err(AppError::Internal("Invalid payment duration".to_string()));
        }
        if plan.grouping_id < 0 || plan.grouping_id >= PaymentGroupType::END as i32 {
            tracing::warn!("Invalid payment group id in update_payment_plan");
            return Err(AppError::Internal("Invalid group id".to_string()));
        }

        let result = self.session
            .query_unpaged(
                "INSERT into mma.payment_plan (school_id, payment_plan_id, base_payment_plan_id, grouping_id, min_age, max_age, working, title, description, cost, duration_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                (&school_id, &plan_id, &base_plan_id, plan.grouping_id, plan.min_age, plan.max_age, plan.working, &plan.title, &plan.description, &plan.cost, plan.duration_id),
            )
            .await.trace()?;

        Ok(())
    }


    pub async fn get_school_current_payment_plans(
        &self,
        school_id: &Uuid,
    ) -> AppResult<Vec<PurchasablePaymentPlanData>> {
        let result = self.session
            .query_unpaged(
                "SELECT payment_plan_id, base_payment_plan_id, grouping_id, min_age, max_age, working, title, description, cost, duration_id FROM mma.payment_plan where school_id = ?;",
                (school_id,),
            )
            .await.trace()?
            .into_rows_result().trace()?;

        let mut plans: Vec<PurchasablePaymentPlanData> = Vec::new();
        for row in result.rows::<PaymentPlanData>().trace()? {
            let plan = row.trace()?;
            let age_match = true;
            
            if age_match {
                let new_plan = PurchasablePaymentPlanData {
                    payment_plan_id: plan.payment_plan_id,
                    base_payment_plan_id: plan.base_payment_plan_id,
                    grouping_id: plan.grouping_id,
                    min_age: plan.min_age,
                    max_age: plan.max_age,
                    working: plan.working,
                    title: plan.title,
                    description: plan.description,
                    cost: plan.cost,
                    duration_id: plan.duration_id,
                    purchasable: age_match,
                    purchasable_message: None
                };
                plans.push(new_plan);
            }
        }
        Ok(plans)

    }



    pub async fn get_purchasable_payment_plans(
        &self,
        user_id: &Uuid,
        school_id: &Uuid,
    ) -> AppResult<Vec<PurchasablePaymentPlanData>> {

        let user_result = self.session
            .query_unpaged(
                "SELECT dob FROM mma.user where user_id = ?;",
                (school_id,),
            )
            .await.trace()?
            .into_rows_result().trace()?;
        let utc_now = Utc::now();
        let mut age_years = None;
        for row in user_result.rows().trace()? {
            let (dob, ) : (Option<NaiveDate>, ) = row.trace()?;
            age_years = //match dob {
                // Some(dob) => {
                    get_naive_age(&dob);
                    // Some(dob.year() - utc_now.year())
                // },
                // None => None
            //};
        }

        let result = self.session
            .query_unpaged(
                "SELECT payment_plan_id, base_payment_plan_id, grouping_id, min_age, max_age, working, title, description, cost, duration_id FROM mma.payment_plan where school_id = ?;",
                (school_id,),
            )
            .await.trace()?
            .into_rows_result().trace()?;

        let mut plans: Vec<PurchasablePaymentPlanData> = Vec::new();
        for row in result.rows::<PaymentPlanData>().trace()? {
            let plan = row.trace()?;
            let age_match = age_check(age_years, plan.min_age, plan.max_age);
            
            if age_match {
                let new_plan = PurchasablePaymentPlanData {
                    payment_plan_id: plan.payment_plan_id,
                    base_payment_plan_id: plan.base_payment_plan_id,
                    grouping_id: plan.grouping_id,
                    min_age: plan.min_age,
                    max_age: plan.max_age,
                    working: plan.working,
                    title: plan.title,
                    description: plan.description,
                    cost: plan.cost,
                    duration_id: plan.duration_id,
                    purchasable: age_match,
                    purchasable_message: None
                };
                plans.push(new_plan);
            }
        }
        Ok(plans)
    }


    pub async fn get_class(&self, class_id: &Uuid, school_id: &Uuid) -> AppResult<Option<ClassData>> {
        let result = self.session
            .query_unpaged("SELECT class_id, venue_id, waiver_id, capacity, publish_mode, price, notify_booking, title, description, styles, grades, deleted_ts, free_lessons FROM mma.class where class_id = ? and school_id = ?", (class_id, school_id)) // Pass the query string and bound values
            .await.trace()?
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
                styles: row.styles, // Initialize with an empty vector
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
                    .await.trace()?
                    .into_rows_result().trace()?;
    
                for row in result.rows().trace()?
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
        let now = get_time();
        let now = scylla::value::CqlTimestamp(now);
        let zero_ts = scylla::value::CqlTimestamp(0);
        let timezone = "Australia/Sydney";

        let result = self.session
            .query_unpaged("SELECT school_id FROM mma.school where school_id = ?", (school_id, )) // Pass the query string and bound values
            .await.trace()?
            .into_rows_result().trace()?;

        if result.rows_num() != 0 {
            return Err(AppError::BadRequest("Trying to create a school when one with that school_id exists already".to_string()));
        }

        self.session
            .query_unpaged(
                "INSERT INTO mma.school (super_user_id, school_id, title, description, created_ts, deleted_ts, timezone) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (super_user_id, school_id, title, description, now, zero_ts, timezone), // Include other fields as per your schema
            )
            .await.trace()?;

        let zero_guuid = Uuid::nil();
        self.session
            .query_unpaged(
                "INSERT INTO mma.user_permission (user_id, club_id, class_id, permission, created_ts) VALUES (?, ?, ?, ?, ?)",
                (super_user_id, zero_guuid, zero_guuid, Permissions::HyperAdmin as i32, now), // Include other fields as per your schema
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
            .await.trace()?
            .into_rows_result().trace()?;

        // let mut class: Option<ClassData> = None;
        for row in result.rows::<StyleData>().trace()?
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
            .await.trace()?            
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


    pub async fn change_user_subscribe_payment_plan(
        &self, 
        user_id: &Uuid,
        subscription: &ChangeUserSubscribePaymentPlan) 
    -> AppResult<()> {

        let result = self.session
        .query_unpaged(
            "UPDATE mma.user_payment_plan SET subscribed = ? where user_id = ? and user_payment_plan_id = ?",
            (subscription.subscribe, user_id, subscription.user_payment_plan_id),
        )
        .await.trace()?;

        Ok(())
    }
    
    pub async fn user_subscribe_payment_plan(
        &self, 
        stripe_client: &StripeClient,
        user_id: &Uuid,
        school_id: &Uuid,
        subscription: &UserSubscribePaymentPlan
    ) -> AppResult<()> {

        let mut age = None;
        // if !subscription.subscribe {
        let result = self.session
            .query_unpaged(
                "SELECT dob FROM mma.user where user_id = ?",
                (user_id, ),
            )
            .await.trace()?
            .into_rows_result().trace()?;
        let utc_now = Utc::now();

        for row in result.rows().trace()?
        {
            let (dob,): (Option<NaiveDate>,) = row.trace()?;
            age = get_naive_age(&dob);
            // age = get_age(&dob_str);
            // let age = Some(dob.year() - utc_now.year());
        }
        // }

        let result = self.session
            .query_unpaged(
                "SELECT payment_plan_id, subscribed, expiration_ts FROM mma.user_payment_plan where user_id = ?",
                (user_id, ),
            )
            .await.trace()?
            .into_rows_result().trace()?;

        let mut has_plan = false;
        let now = get_time();
        for row in result.rows().trace()?
        {
            let (payment_plan_id, subscribed, expiration_ts): (Uuid, bool, CqlTimestamp) = row.trace()?;

            if payment_plan_id == subscription.payment_plan_id && expiration_ts.0 >= now {
                // if subscribed != subscription.subscribe {
                //     let result = self.session
                //         .query_unpaged(
                //             "update mma.user_payment_plan subscribed = ? where user_id = ? and payment_plan_id = ?",
                //             (subscription.subscribe, user_id, payment_plan_id),
                //         )
                //         .await.trace()?;
                // }

                tracing::info!("Already subscribed expired by {}", expiration_ts.0 - now);
                return Ok(()); // Already subscribed to this payment plan
            }
            // if payment_plan_id == subscription.payment_plan_id && !subscription.subscribe && !subscribed {
            //     // User was subscribed but has already unsubscribed
            //     tracing::info!("Already existing - + unsubscribed");

            //     return Ok(());
            // }

            has_plan = true;
        }

        // if !has_plan && !subscription.subscribe {
        //     tracing::info!("Already unsubscribed");
        //     return Ok(()); // Already unsubscribed to this payment plan
        // }

        
        // school_id uuid, payment_plan_id uuid, base_payment_plan_id uuid, grouping_id int, min_age int, max_age int, working boolean, title text, description text, cost decimal, duration_id int, deleted_ts timestamp, created_ts timestamp
        let result = self.session
            .query_unpaged(
                "SELECT deleted_ts, cost, min_age, max_age, duration_id, grouping_id FROM mma.payment_plan where school_id = ? and base_payment_plan_id = ? and payment_plan_id = ?",
                (school_id, &subscription.base_payment_plan_id, &subscription.payment_plan_id),
            )
            .await.trace()?
            .into_rows_result().trace()?;

        let mut has_rows = false;
        for row in result.rows().trace()?
        {
            let (deleted_ts, cost, min_age, max_age, duration_id, grouping_id ): (Option<CqlTimestamp>, BigDecimal, Option<i32>, Option<i32>, i32, i32) = row.trace()?;
            if deleted_ts.is_some() {
                return Err(AppError::BadRequest("Payment plan has been deleted".to_string()))
            }

            let age_check = age_check(age, min_age, max_age);
            if !age_check {
                return Err(AppError::BadRequest("Users age does not allow for subscription to this payment_method".to_string()))
            }

            let mut group_members = Vec::new();
            group_members.push(user_id);

            //stripe_client
            let result = self.pay_pass(
                user_id,
                school_id,
                stripe_client,
                &cost,
                &subscription.base_payment_plan_id,
                &subscription.payment_plan_id,
                duration_id,
                grouping_id,
                &group_members
            ).await.trace()?;

            if !result {
                tracing::info!("Payment failed");
                return Err(AppError::BadRequest("Payment operation failed".to_string()))
            }

            tracing::info!("No problems with paying");
            return Ok(());


            has_rows = true;
            break;
        }
        if !has_rows {
            return Err(AppError::BadRequest("Payment plan does not exist".to_string()))
        }
        

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
            .await.trace()?            
            .into_rows_result().trace()?;

        let mut styles: Vec<StyleData> = Vec::new();
        for row in result.rows::<StyleData>().trace()?
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
            .await.trace()?
            .into_rows_result().trace()?;
        
        // Extract row data
        let mut logged_user_id: Option<Uuid> = None;
        let mut is_valid = false;
        
        for row in result.rows().trace()? {
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
                .await.trace()?
                .into_rows_result().trace()?;

                let mut school_id: Option<Uuid> = None;
                for row in result.rows().trace()? {
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
            .await.trace()?
            .into_rows_result().trace()?;
        
        // Check if code exists, is not expired, and is not used
        let mut is_valid = false;
        let mut first_name: Option<String> = None;
        let mut surname: Option<String> = None;
        let mut password_hash: Option<String> = None;
        let mut school_id: Option<Uuid> = None;
        let mut new_school: bool = false;
        let mut user_id: Option<Uuid> = None;
        for row in result.rows().trace()? {
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

    // Get school settings
    pub async fn get_school_settings(&self, school_id: &Uuid) -> AppResult<Option<crate::api::SchoolSettings>> {
        let result = self.session
            .query_unpaged(
                "SELECT title, timezone, stripe_publishable_key, stripe_secret_key, stripe_webhook_secret 
                 FROM mma.school WHERE school_id = ?",
                (school_id,),
            )
            .await.trace()?
            .into_rows_result().trace()?;

        for row in result.rows().trace()? {
            let (school_name, timezone, stripe_publishable_key, stripe_secret_key, stripe_webhook_secret): 
                (Option<String>, Option<String>, Option<String>, Option<String>, Option<String>) = row.trace()?;

            // We need to hide the secret key -- so lets * all but the first 3 chars and last 3 chars
            let stripe_secret_key = stripe_secret_key.map(|s| {
                   "••••••••".to_string();
            });

            return Ok(Some(crate::api::SchoolSettings {
                school_name,
                timezone,
                stripe_publishable_key,
                stripe_secret_key: if stripe_secret_key.is_some() { Some("••••••••".to_string()) } else { None },
                stripe_webhook_secret: if stripe_webhook_secret.is_some() { Some("••••••••".to_string()) } else { None },
            }));
        }
        
        Ok(None)
    }

    // Update school settings
    pub async fn update_school_settings(
        &self, 
        school_id: &Uuid, 
        settings: &crate::api::SchoolSettingsRequest
    ) -> AppResult<()> {
        // First, get existing settings to preserve secrets if not being updated
        let existing = self.session
            .query_unpaged(
                "SELECT stripe_secret_key, stripe_webhook_secret FROM mma.school WHERE school_id = ?",
                (school_id,),
            )
            .await.trace()?
            .into_rows_result().trace()?;

        let mut secret_key = settings.stripe_secret_key.clone();
        let mut webhook_secret = settings.stripe_webhook_secret.clone();

        // Check that the key starts with sk_
        if let Some(ref key) = secret_key {
            if key == "••••••••" { 
                secret_key = Some("••••••••".to_string());
            } else if key.is_empty() {
                return Err(AppError::BadRequest("Stripe secret key cannot be empty".to_string()));
            } else if !key.starts_with("sk_") {
                return Err(AppError::BadRequest("Stripe secret key must start with 'sk_'".to_string()));
            }
        }
        // Check that the webhook secret starts with whsec_
        if let Some(ref key) = webhook_secret {
            if !key.starts_with("whsec_") {
                return Err(AppError::BadRequest("Stripe webhook secret must start with 'whsec_'".to_string()));
            }
        }



        // Check the public key starts with pk_
        if let Some(ref key) = settings.stripe_publishable_key {
            if !key.starts_with("pk_") {
                return Err(AppError::BadRequest("Stripe publishable key must start with 'pk_'".to_string()));
            }
        }   

        // If existing record exists and new values are masked, preserve existing values
        for row in existing.rows().trace()? {
            let (existing_secret, existing_webhook): (Option<String>, Option<String>) = row.trace()?;
            if secret_key.as_ref().map(|s| s.as_str()) == Some("••••••••") {
                secret_key = existing_secret;
            }
            if webhook_secret.as_ref().map(|s| s.as_str()) == Some("••••••••") {
                webhook_secret = existing_webhook;
            }
            break; // Only process first row
        }

        self.session
            .query_unpaged(
                "INSERT INTO mma.school (school_id, title, timezone, stripe_publishable_key, stripe_secret_key, stripe_webhook_secret) 
                 VALUES (?, ?, ?, ?, ?, ?)",
                (
                    school_id,
                    &settings.school_name,
                    &settings.timezone,
                    &settings.stripe_publishable_key,
                    &secret_key,
                    &webhook_secret,
                ),
            )
            .await.trace()?;

        Ok(())
    }


}
