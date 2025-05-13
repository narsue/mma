pub mod handlers {
    use actix_web::{post, get, web, http::header::CONTENT_TYPE, HttpRequest, HttpResponse, cookie::{Cookie, SameSite}};
    use std::sync::Arc;
    use uuid::Uuid;
    use crate::state::StoreStateManager;
    // use crate::error::AppError;
    use crate::api::{
        LoginRequest, LoginResponse, CreateUserRequest, CreateUserResponse, ContactForm,
        GetUserProfileResponse, UpdateUserProfileRequest, UpdateUserProfileResponse,
        ChangePasswordRequest, ChangePasswordResponse, GetWaiverResponse,
        AcceptWaiverRequest, AcceptWaiverResponse, CreateWaiverResponse, CreateWaiverRequest,  // Re-using or adjusting generic response
        CreateClassRequest, CreateClassResponse, ClassFrequency, ClassFrequencyRequest, 
        ClassData, CreateVenueRequest, CreateVenueResponse, VenueData, CreateStyleRequest, CreateStyleResponse, StyleData
    };
    use chrono::{NaiveDate, NaiveTime, Utc};
    use bigdecimal::BigDecimal;
    use crate::auth::LoggedUser;
    use crate::db::{verify_password, hash_password};
    use crate::templates::{TemplateCache, get_template_content};
    use actix_web::error::Error as ActixError;
    use crate::error::{AppError, Result as AppResult};
    use actix_web::error::ErrorInternalServerError;

    // Get User Profile Handler ---
    #[get("/api/user/profile_data")]
    pub async fn get_user_profile_data(
        state_manager: web::Data<Arc<StoreStateManager>>,
        mut user: LoggedUser, // Authenticate the request
    ) -> Result<HttpResponse, actix_web::Error> {
        // Validate the session and get the user_id
        let user_id = user.validate(&state_manager).await?;

        // Fetch the user profile from the database
        match state_manager.db.get_user_profile(user_id).await {
            Ok(Some(profile)) => {
                Ok(HttpResponse::Ok().json(GetUserProfileResponse {
                    success: true,
                    error_message: None,
                    user_profile: Some(profile),
                }))
            },
            Ok(None) => {
                // This case should ideally not happen if LoggedUser validation passed
                tracing::error!("Authenticated user ID {} not found in profile data!", user_id);
                Ok(HttpResponse::InternalServerError().json(GetUserProfileResponse {
                    success: false,
                    error_message: Some("User profile not found.".to_string()),
                    user_profile: None,
                }))
            },
            Err(e) => {
                tracing::error!("Database error fetching profile for {}: {:?}", user_id, e);
                Ok(HttpResponse::InternalServerError().json(GetUserProfileResponse {
                    success: false,
                    error_message: Some("Failed to retrieve user profile.".to_string()),
                    user_profile: None,
                }))
            }
        }
    }


    // Update User Profile Handler ---
    #[post("/api/user/update_profile")]
    pub async fn update_user_profile(
        state_manager: web::Data<Arc<StoreStateManager>>,
        mut user: LoggedUser, // Authenticate the request
        update_data: web::Json<UpdateUserProfileRequest>,
    ) -> Result<HttpResponse, actix_web::Error> {
        // Validate the session and get the user_id
        let user_id = user.validate(&state_manager).await?;
        let req_data = update_data.into_inner();

        // Perform the update
        match state_manager.db.update_user_profile(user_id, &req_data).await {
            Ok(_) => {
                Ok(HttpResponse::Ok().json(UpdateUserProfileResponse {
                    success: true,
                    error_message: None,
                }))
            },
            Err(e) => {
                tracing::error!("Database error updating profile for {}: {:?}", user_id, e);
                Ok(HttpResponse::InternalServerError().json(UpdateUserProfileResponse {
                    success: false,
                    error_message: Some("Failed to update user profile.".to_string()),
                }))
            }
        }
    }

    // Change Password Handler ---
    #[post("/api/user/change_password")]
    pub async fn change_password(
        state_manager: web::Data<Arc<StoreStateManager>>,
        mut user: LoggedUser, // Authenticate the request
        password_data: web::Json<ChangePasswordRequest>,
    ) -> Result<HttpResponse, ActixError> { // Handler returns Result<HttpResponse, ActixError>
    
        // Validate the session and get the user_id
        // Assuming user.validate returns Result<Uuid, ActixError>.
        // Remove the .map_err call.
        let user_id = user.validate(&state_manager).await?; // This should now compile
    
        let req_data = password_data.into_inner();
    
        // 1. Get the stored password hash
        // Call the function and store the AppResult WITHOUT using ?.
        let get_hash_result = state_manager.db.get_password_hash(user_id).await;
    
        // Use a match statement to handle the AppResult<Option<String>, AppError>
        let stored_hash = match get_hash_result {
            Ok(Some(hash)) => {
                // Successfully got a hash, continue with the hash value
                hash
            },
            Ok(None) => {
                // get_password_hash returned Ok(None) (user not found by ID in DB)
                // This is an application-level condition, return an HTTP response indicating the error
                tracing::error!("Authenticated user ID {} not found in DB after auth!", user_id);
                // Return an HTTP error response wrapped in Ok() because the handler's
                // success type is HttpResponse.
                return Ok(HttpResponse::InternalServerError().json(ChangePasswordResponse {
                    success: false,
                    error_message: Some("User data inconsistency.".to_string()),
                }));
            },
            Err(app_err) => {
                // get_password_hash returned Err(AppError)
                // Manually convert the AppError into the handler's error type (ActixError)
                // This works because AppError derives Error via thiserror and ActixError has From<Error + Send + Sync + 'static>.
                tracing::error!("Error fetching password hash for user {}: {:?}", user_id, app_err); // Log the original error
                // This is the line that should now work correctly because we are
                // calling ActixError::from directly on the AppError in a non-propagation context.
                return Err(actix_web::error::ErrorInternalServerError(app_err))
            }
        };

        // 2. Verify the current password
        match verify_password(&req_data.current_password, &stored_hash) {
            Ok(is_valid) => {
                if !is_valid {
                    return Ok(HttpResponse::Unauthorized().json(ChangePasswordResponse {
                        success: false,
                        error_message: Some("Incorrect current password.".to_string()),
                    }));
                }
            },
            Err(e) => {
                tracing::error!("Password verification error for user {}: {:?}", user_id, e);
                return Ok(HttpResponse::InternalServerError().json(ChangePasswordResponse {
                    success: false,
                    error_message: Some("Password verification failed.".to_string()),
                }));
            }
        }

        // 3. Hash the new password
        let new_password_hash = match hash_password(&req_data.new_password) {
            Ok(hash) => hash,
            Err(e) => {
                tracing::error!("Error hashing new password for user {}: {:?}", user_id, e);
                return Ok(HttpResponse::InternalServerError().json(ChangePasswordResponse {
                    success: false,
                    error_message: Some("Failed to process new password.".to_string()),
                }));
            }
        };

        // 4. Update the password hash in the database
        match state_manager.db.update_password_hash(user_id, new_password_hash).await {
            Ok(_) => {
                // --- Security Enhancement: Invalidate other sessions ---
                // Forces user to re-login on other devices after password change
                if let Err(e) = state_manager.db.invalidate_all_user_sessions(user_id).await {
                    // Log the error but don't necessarily fail the password change itself
                    tracing::warn!("Failed to invalidate other sessions for user {} after password change: {:?}", user_id, e);
                }
                // Note: The current session cookie will still be valid until it expires or they explicitly log out THIS session.

                Ok(HttpResponse::Ok().json(ChangePasswordResponse {
                    success: true,
                    error_message: None,
                }))
            },
            Err(e) => {
                tracing::error!("Database error updating password for {}: {:?}", user_id, e);
                Ok(HttpResponse::InternalServerError().json(ChangePasswordResponse {
                    success: false,
                    error_message: Some("Failed to change password in database.".to_string()),
                }))
            }
        }
    }






    // --- New CSS Handler ---
    #[get("/style.css")]
    pub async fn serve_css(cache: web::Data<TemplateCache>) -> HttpResponse {
        match get_template_content(&cache, "style.css") {
            Ok(content) => HttpResponse::Ok()
                // Set the correct Content-Type for CSS files
                .content_type("text/css")
                .body(content),
            Err(resp) => resp, // Return 404 or other error from get_template_content
        }
    }

    #[get("/")]
    pub async fn home_page(cache: web::Data<TemplateCache>) -> HttpResponse {
        match get_template_content(&cache, "home.html") {
            Ok(content) => HttpResponse::Ok()
                .insert_header((CONTENT_TYPE, "text/html; charset=utf-8"))
                .body(content),
            Err(resp) => resp, // Return the 404 response from the helper
        }
    }

    #[get("/login")]
    pub async fn login_signup_page(cache: web::Data<TemplateCache>) -> HttpResponse {
         match get_template_content(&cache, "login.html") {
            Ok(content) => HttpResponse::Ok()
                .insert_header((CONTENT_TYPE, "text/html; charset=utf-8"))
                .body(content),
            Err(resp) => resp,
        }
    }

    #[get("/gym-signup")]
    pub async fn gym_signup_page(cache: web::Data<TemplateCache>) -> HttpResponse {
         match get_template_content(&cache, "gym_signup.html") {
            Ok(content) => HttpResponse::Ok()
                .insert_header((CONTENT_TYPE, "text/html; charset=utf-8"))
                .body(content),
            Err(resp) => resp,
        }
    }

    #[get("/contact")]
    pub async fn contact_page(cache: web::Data<TemplateCache>) -> HttpResponse {
         match get_template_content(&cache, "contact.html") {
            Ok(content) => HttpResponse::Ok()
                .insert_header((CONTENT_TYPE, "text/html; charset=utf-8"))
                .body(content),
            Err(resp) => resp,
        }
    }

    #[get("/portal")]
    // This route requires authentication. Use LoggedUser to protect it.
    pub async fn portal_page(
        state_manager: web::Data<Arc<StoreStateManager>>, // Needed for user.validate()
        mut user: LoggedUser, // This extracts the session cookie and provides the token
        cache: web::Data<TemplateCache> // Needed to serve the template
    ) -> Result<HttpResponse, actix_web::Error> {
        // Validate the user's session. If invalid, it returns Unauthorized.
        let _user_id = user.validate(&state_manager).await?;

        // If validation succeeds, serve the portal HTML
        match get_template_content(&cache, "portal.html") {
            Ok(content) => Ok(HttpResponse::Ok()
                .insert_header((CONTENT_TYPE, "text/html; charset=utf-8"))
                .body(content)),
            Err(resp) => Ok(resp), // Return the 404 response from the helper
        }
    }


    #[post("/contact/submit")]
    pub async fn contact_submit(
        form: web::Form<ContactForm>,
        cache: web::Data<TemplateCache> // <-- Inject cache here too
    ) -> HttpResponse {
        tracing::info!(
            "Received contact form submission: Name={}, Email={}, Message={}",
            form.name,
            form.email,
            form.message
        );

        // In a real app, send email here...

        // Get confirmation template and replace placeholder
        match get_template_content(&cache, "contact_confirmation.html") {
             Ok(template_content) => {
                 let body = template_content.replace("{email}", &form.email);
                 HttpResponse::Ok()
                    .insert_header((CONTENT_TYPE, "text/html; charset=utf-8"))
                    .body(body)
             },
             Err(resp) => resp, // Return 404 if confirmation template is missing
        }
    }


    #[post("/api/user/create")]
    pub async fn create_user(
        state_manager: web::Data<Arc<StoreStateManager>>,
        request: web::Json<CreateUserRequest>,
    ) -> HttpResponse {
        let req = request.into_inner();
        
        // Basic validation
        if req.email.is_empty() || req.password.is_empty() || req.first_name.is_empty() || req.surname.is_empty() {
            return HttpResponse::BadRequest().json(CreateUserResponse {
                success: false,
                error_message: Some("Required fields missing".to_string()),
                user_id: None,
            });
        }
        
        // Create the user using our database connector
        let result = state_manager.db.create_user(
            &req.email,
            &req.password,
            &req.first_name,
            &req.surname,
            req.gender.as_deref(),
            req.phone.as_deref(),
            req.dob.as_deref(),
            req.address.as_deref(),
            req.suburb.as_deref(),
            req.emergency_name.as_deref(),
            req.emergency_relationship.as_deref(),
            req.emergency_phone.as_deref(),
            req.emergency_medical.as_deref(),
        ).await;
        
        match result {
            Ok(user_id) => {
                HttpResponse::Created().json(CreateUserResponse {
                    success: true,
                    error_message: None,
                    user_id: Some(user_id),
                })
            },
            Err(e) => {
                // Check for specific errors
                let error_message = match e {
                    AppError::Internal(msg) if msg.contains("already registered") => {
                        "Email already registered".to_string()
                    },
                    _ => {
                        tracing::error!("Failed to create user: {:?}", e);
                        "Failed to create user".to_string()
                    }
                };
                
                HttpResponse::BadRequest().json(CreateUserResponse {
                    success: false,
                    error_message: Some(error_message),
                    user_id: None,
                })
            }
        }
    }


    #[post("/api/user/login")]
    pub async fn user_login(
        state_manager: web::Data<Arc<StoreStateManager>>,
        request: web::Json<LoginRequest>,
        req: HttpRequest, // Added to get request info
    ) -> HttpResponse {
        let login_req = request.into_inner();
        
        // Extract IP and user agent
        let ip = req.connection_info().realip_remote_addr()
            .map(|ip| ip.to_string());
        let user_agent = req.headers().get(actix_web::http::header::USER_AGENT)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());
        
        // Authenticate user
        match state_manager.authenticate_user(
            login_req.email,
            login_req.password,
            ip,
            user_agent
        ).await {
            Ok((user_id, session_token)) => {
                // Set the session token as a cookie
                let cookie = Cookie::build("session", session_token.clone())
                    .path("/")
                    .secure(true)  // Only send over HTTPS
                    .http_only(true)  // Not accessible to JavaScript
                    .same_site(SameSite::Strict)  // Prevent CSRF
                    .max_age(time::Duration::hours(24))
                    .finish();
                
                // Build the user_id cookie
                let user_id_cookie = Cookie::build("user_id", user_id.to_string()) // Store user_id as a string
                    .path("/") // Accessible from the root path
                    .secure(true)  // Only send over HTTPS
                    .http_only(false)  // *** Set this FALSE if frontend JS needs to read it ***
                                    // (Required by the LoggedUser extractor reading it from the cookie)
                    .same_site(SameSite::Strict)  // Prevent CSRF
                    .max_age(time::Duration::hours(24)) // Match session expiry
                    .finish();

                HttpResponse::Ok()
                    .cookie(cookie)
                    .cookie(user_id_cookie)
                    .json(LoginResponse {
                        success: true,
                        error_message: None,
                        token: Some(session_token),
                        user_id: Some(user_id),
                    })
            },
            Err(e) => {
                tracing::warn!("Login failed: {:?}", e);
                HttpResponse::Unauthorized().json(LoginResponse {
                    success: false,
                    error_message: Some(e.to_string()),
                    token: None,
                    user_id: None,
                })
            }
        }
    }


    #[post("/api/user/logout")]
    pub async fn user_logout(
        state_manager: web::Data<Arc<StoreStateManager>>,
        mut user: LoggedUser,
        req: HttpRequest,
    ) -> Result<HttpResponse, actix_web::Error> {
        // Validate the session
        let user_id = user.validate(&state_manager).await?;
        
        // Get session token from cookie
        if let Some(cookie) = req.cookie("session") {
            let session_token = cookie.value();
            
            // Invalidate the session
            if let Err(e) = state_manager.db.invalidate_session(user_id, session_token).await {
                tracing::error!("Failed to invalidate session: {:?}", e);
                return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                    "success": false,
                    "error_message": "Failed to logout"
                })));
            }
            
            // Remove the cookie
            let removal_cookie = Cookie::build("session", "")
                .path("/")
                .max_age(time::Duration::seconds(0))
                .finish();
            
            return Ok(HttpResponse::Ok()
                .cookie(removal_cookie)
                .json(serde_json::json!({
                    "success": true
                })));
        }
        
        Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "error_message": "No active session"
        })))
    }
    
    // Example of a protected endpoint
    #[get("/api/user/profile")]
    pub async fn user_profile(state_manager: web::Data<Arc<StoreStateManager>>, mut user: LoggedUser) -> Result<HttpResponse, actix_web::Error> {
        println!("User profile endpoint hit");
        // Validate the session
        let user_id = user.validate(&state_manager).await?;
        
        // Now we can use the user_id to fetch user data
        // ...
        
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "user_id": user_id
        })))
    }
    
    #[get("/api/waiver/get_latest_waiver")]
    pub async fn get_latest_waiver(
        state_manager: web::Data<Arc<StoreStateManager>>,
        mut user: LoggedUser,
    ) -> Result<HttpResponse, actix_web::Error> {
        // Validate the session
        let user_id = user.validate(&state_manager).await?;
        
        // Fetch the latest waiver for the user
        match state_manager.db.get_latest_waiver(None, None, None).await {
            Ok(Some(waiver)) => {
                Ok(HttpResponse::Ok().json(GetWaiverResponse {
                    success: true,
                    error_message: None,
                    waiver: Some(waiver.1),
                    waiver_id: Some(waiver.0),
                }))
            },
            Ok(None) => {
                Ok(HttpResponse::NotFound().json(GetWaiverResponse {
                    success: false,
                    error_message: Some("No waiver found.".to_string()),
                    waiver: None,
                    waiver_id: None,
                }))
            },
            Err(e) => {
                tracing::error!("Database error fetching waiver for {}: {:?}", user_id, e);
                Ok(HttpResponse::InternalServerError().json(GetWaiverResponse {
                    success: false,
                    error_message: Some("Failed to retrieve waiver.".to_string()),
                    waiver: None,
                    waiver_id: None,
                }))
            }
        }
    }


    
    // Handler for the user to accept a waiver
    #[post("/api/user/accept_waiver")]
    pub async fn accept_waiver_handler(
        state_manager: web::Data<Arc<StoreStateManager>>,
        mut user: LoggedUser, // Require user to be logged in
        waiver_data: web::Json<AcceptWaiverRequest>,
    ) -> Result<HttpResponse, ActixError> {
        // Validate the session and get the user_id
        let user_id = user.validate(&state_manager).await
            .map_err(|app_err| ErrorInternalServerError(app_err))?; // Convert potential AppError from validate

        let req_data = waiver_data.into_inner();
        let accepted_waiver_id = req_data.waiver_id;

        // Optional: Verify the accepted_waiver_id against the current latest waiver ID
        // This prevents a user from accepting an outdated waiver if a new one has been published
        let latest_waiver_check: AppResult<Option<(Uuid, String, String)>> = state_manager.db.get_latest_waiver(None, None, None).await;

        let latest_waiver_id = match latest_waiver_check {
            Ok(Some((id, _, _))) => id,
            Ok(None) => {
                // No current waiver exists, but user tried to accept one.
                // This is a client issue or timing issue.
                tracing::warn!("User {} attempted to accept waiver ID {} but no current waiver exists.", user_id, accepted_waiver_id);
                return Ok(HttpResponse::BadRequest().json(AcceptWaiverResponse {
                    success: false,
                    error_message: Some("No active waiver is available to accept.".to_string()),
                }));
            },
            Err(app_err) => {
                // DB error during latest waiver check
                tracing::error!("Database error checking latest waiver during acceptance for user {}: {:?}", user_id, app_err);
                return Err(ErrorInternalServerError(app_err)); // Propagate DB error
            }
        };

        if accepted_waiver_id != latest_waiver_id {
            // The ID the user accepted does not match the current latest ID
            tracing::warn!("User {} attempted to accept outdated waiver ID {}. Current is {}.", user_id, accepted_waiver_id, latest_waiver_id);
            return Ok(HttpResponse::Conflict().json(AcceptWaiverResponse { // 409 Conflict
                success: false,
                error_message: Some("The waiver version you accepted is outdated. Please refresh and accept the current version.".to_string()),
            }));
        }

        // If verification passed, update the user's waiver_id
        let update_result: AppResult<()> = state_manager.db.insert_user_accept_waiver_id(user_id, accepted_waiver_id).await;

        match update_result {
            Ok(_) => {
                // Update successful
                tracing::info!("User {} successfully accepted waiver ID {}", user_id, accepted_waiver_id);
                Ok(HttpResponse::Ok().json(AcceptWaiverResponse {
                    success: true,
                    error_message: None,
                }))
            }
            Err(app_err) => {
                // Database error during update
                tracing::error!("Database error updating waiver_id for user {}: {:?}", user_id, app_err);
                Err(ErrorInternalServerError(app_err)) // Manually convert AppError to ActixError
            }
        }
    }


    // Handler to create a new waiver
    // This should likely be restricted to admin users if you have roles
    #[post("/api/waiver/create")]
    pub async fn create_waiver_handler(
        state_manager: web::Data<Arc<StoreStateManager>>,
        mut user: LoggedUser, // Protect the endpoint (consider checking for admin role)
        waiver_data: web::Json<CreateWaiverRequest>,
    ) -> Result<HttpResponse, ActixError> {
        // Validate the session and get the user_id
        let user_id = user.validate(&state_manager).await
            .map_err(|app_err| ErrorInternalServerError(app_err))?;

        // *** Optional: Check user role here to ensure only authorized users can create waivers ***
        // If user.role is not "admin", return HttpResponse::Forbidden()

        let req_data = waiver_data.into_inner();
        let waiver_content = req_data.content.trim();
        let waiver_title = req_data.title.trim();

        if waiver_content.is_empty() {
            return Ok(HttpResponse::BadRequest().json(CreateWaiverResponse {
                success: false,
                id: None,
                error_message: Some("Waiver content cannot be empty.".to_string()),
            }));
        }

        if waiver_title.is_empty() {
            return Ok(HttpResponse::BadRequest().json(CreateWaiverResponse {
                success: false,
                id: None,
                error_message: Some("Waiver title cannot be empty.".to_string()),
            }));
        }

        let new_waiver_id = Uuid::new_v4();
        // You'll need to implement the logic to insert the new waiver into the database
        // and mark it as the current one, potentially setting the previous 'is_current' to false.
        // This might require multiple DB queries.

        // Example DB interaction (you'll need to implement this in your db.rs)
        // pub async fn create_new_waiver(&self, id: Uuid, content: &str) -> AppResult<()> { ... }
        let create_result: AppResult<()> = state_manager.db.create_new_waiver(user_id, new_waiver_id, waiver_title.to_string(), waiver_content.to_string()).await;


        match create_result {
            Ok(_) => {
                tracing::info!("New waiver created with ID {}", new_waiver_id);
                Ok(HttpResponse::Ok().json(CreateWaiverResponse {
                    success: true,
                    id: Some(new_waiver_id),
                    error_message: None,
                }))
            }
            Err(app_err) => {
                tracing::error!("Database error creating new waiver: {:?}", app_err);
                Err(ErrorInternalServerError(app_err))
            }
        }
    }



    // --- Class Creation Handler ---
    #[post("/api/class/create")]
    pub async fn create_class_handler(
        state_manager: web::Data<Arc<StoreStateManager>>,
        mut user: LoggedUser, // Authenticate the request
        class_data: web::Json<CreateClassRequest>, // Extract JSON request body
    ) -> Result<HttpResponse, ActixError> { // Handler returns Result<HttpResponse, ActixError>

        // 1. Validate the session and get the creator user_id
        let creator_user_id = user.validate(&state_manager).await
            .map_err(|app_err| ErrorInternalServerError(app_err))?; // Convert potential AppError from validate

        let req_data = class_data.into_inner(); // Get the raw request data

        // 2. Validate and parse incoming data
        // You might want more robust validation here (e.g., check min/max values, non-empty strings)

        // Generate a unique ID for the new class
        let class_id = Uuid::new_v4();

        // Parse the frequency dates and times from strings
        let mut parsed_frequency = Vec::new();
        for freq_req in req_data.frequency {
            let start_date_naive = match NaiveDate::parse_from_str(&freq_req.start_date, "%Y-%m-%d") {
                Ok(date) => date,
                Err(e) => {
                    tracing::warn!("Failed to parse start_date '{}': {:?}", freq_req.start_date, e);
                    // Return a BadRequest error for invalid input format
                    return Ok(HttpResponse::BadRequest().json(CreateClassResponse {
                        success: false,
                        class_id: None,
                        error_message: Some(format!("Invalid start date format: {}. Expected YYYY-MM-DD", freq_req.start_date)),
                    }));
                }
            };

            let end_date_naive = match NaiveDate::parse_from_str(&freq_req.end_date, "%Y-%m-%d") {
                Ok(date) => date,
                Err(e) => {
                    tracing::warn!("Failed to parse end_date '{}': {:?}", freq_req.end_date, e);
                    // Return a BadRequest error for invalid input format
                    return Ok(HttpResponse::BadRequest().json(CreateClassResponse {
                        success: false,
                        class_id: None,
                        error_message: Some(format!("Invalid end date format: {}. Expected YYYY-MM-DD", freq_req.end_date)),
                    }));
                }
            };

            let start_time_naive = match NaiveTime::parse_from_str(&freq_req.start_time, "%H:%M:%S") {
                Ok(time) => time,
                Err(e) => {
                    tracing::warn!("Failed to parse start_time '{}': {:?}", freq_req.start_time, e);
                    // Return a BadRequest error for invalid input format
                    return Ok(HttpResponse::BadRequest().json(CreateClassResponse {
                        success: false,
                        class_id: None,
                        error_message: Some(format!("Invalid start time format: {}. Expected HH:MM:SS", freq_req.start_time)),
                    }));
                }
            };

            let end_time_naive = match NaiveTime::parse_from_str(&freq_req.end_time, "%H:%M:%S") {
                Ok(time) => time,
                Err(e) => {
                    tracing::warn!("Failed to parse end_time '{}': {:?}", freq_req.end_time, e);
                    // Return a BadRequest error for invalid input format
                    return Ok(HttpResponse::BadRequest().json(CreateClassResponse {
                        success: false,
                        class_id: None,
                        error_message: Some(format!("Invalid end time format: {}. Expected HH:MM:SS", freq_req.end_time)),
                    }));
                }
            };

            // Check end date / time is after start date / time
            if end_date_naive < start_date_naive || (end_date_naive == start_date_naive && end_time_naive <= start_time_naive) {
                tracing::warn!("End date/time must be after start date/time");
                return Ok(HttpResponse::BadRequest().json(CreateClassResponse {
                    success: false,
                    class_id: None,
                    error_message: Some("End date/time must be after start date/time".to_string()),
                }));
            }

            // Push the parsed, strongly typed frequency into the vector
            parsed_frequency.push(ClassFrequency { // Use the struct defined in db.rs
                frequency: freq_req.frequency,
                start_date: start_date_naive,
                end_date: end_date_naive,
                start_time: start_time_naive,
                end_time: end_time_naive,
            });
        }

        let price: Option<BigDecimal> = match req_data.price {
            Some(price_str) => {
                match price_str.parse::<BigDecimal>() {
                    Ok(price) => Some(price),
                    Err(e) => {
                        tracing::warn!("Failed to parse price '{}': {:?}", price_str, e);
                        // Return a BadRequest error for invalid input format
                        return Ok(HttpResponse::BadRequest().json(CreateClassResponse {
                            success: false,
                            class_id: None,
                            error_message: Some(format!("Invalid price format: {}", price_str)),
                        }));
                    }
                }
            },
            None => None, // Default value if not provided
        };
        // pub async fn create_new_class(&self, creator_user_id: Uuid, class_id: Uuid, title: String, description: String, venue_id: Uuid, style_ids :&Vec<Uuid>, grading_ids :&Vec<Uuid>, price: BigDecimal, publish_mode: i32, capacity: i32, class_frequency: &Vec<ClassFrequency>, notify_booking: bool) -> AppResult<()> {

        // 3. Call the database function to create the class and related entries
        let create_result: AppResult<()> = state_manager.db.create_new_class(
            creator_user_id,
            class_id, // Pass the generated class_id
            req_data.title,
            req_data.description,
            req_data.venue_id,
            &req_data.style_ids, // Pass slices
            &req_data.grading_ids, // Pass slices
            price,
            req_data.publish_mode,
            req_data.capacity,
            &parsed_frequency, // Pass the parsed frequency as a slice
            req_data.notify_booking,
            req_data.waiver_id, // Pass optional waiver_id
        ).await;


        // 4. Handle the result of the database operation
        match create_result {
            Ok(_) => {
                // Class created successfully
                tracing::info!("Class {} created successfully by user {}", class_id, creator_user_id);
                // Return a success response with the newly created class ID
                Ok(HttpResponse::Ok().json(CreateClassResponse {
                    success: true,
                    class_id: Some(class_id),
                    error_message: None,
                }))
            }
            Err(app_err) => {
                // Database error occurred during creation
                tracing::error!("Database error creating class for user {}: {:?}", creator_user_id, app_err);
                // Manually convert AppError to ActixError using ErrorInternalServerError
                Err(ErrorInternalServerError(app_err))
            }
        }
    }

    // --- Get Class List Handler ---
    #[get("/api/class/get_list")] // Define the GET endpoint path
    pub async fn get_class_list_handler(
        state_manager: web::Data<Arc<StoreStateManager>>, // State manager for DB access
        _user: LoggedUser, // Require user to be logged in (authentication), but don't need user_id for this list
        // query_params: Query<GetClassesQueryParams>, // Extract query parameters from the URL
    ) -> Result<HttpResponse, ActixError> { // Handler returns Result<HttpResponse, ActixError>

        // The LoggedUser extractor handles the authentication check.
        // If authentication fails, Actix Web will return an Unauthorized error
        // before the handler body executes. The _user variable is unused
        // if the user_id isn't needed for filtering *this* specific list endpoint.

        // let filters = query_params.into_inner(); // Extract the query parameter struct

        // tracing::info!("Received request for class list with filters: only_future={}, publish_mode={:?}",
        //             filters.only_future, filters.publish_mode);

        // Call the database function to get classes based on the provided filters
        let classes_result: AppResult<Vec<ClassData>> = state_manager.db.get_classes(
            true,
            None,
        ).await; // Use '?' to propagate AppError from get_classes - OH WAIT, get_classes returns AppResult, need match/map_err

        // Handle the result of the database operation explicitly
        match classes_result {
            Ok(classes) => {
                // Database function succeeded, returns a Vec<ClassData> (could be empty)
                // tracing::info!("Successfully fetched {} classes.", classes.len());
                // Return the vector of ClassData as a JSON array with 200 OK status
                Ok(HttpResponse::Ok().json(classes))
            },
            Err(app_err) => {
                // A database error (AppError) occurred
                tracing::error!("Database error fetching class list: {:?}", app_err);
                // Convert the AppError into an ActixError representing a 500 Internal Server Error
                Err(ErrorInternalServerError(app_err))
            }
        }
    }
    

    // Create Venue
    #[post("/api/venue/create")]
    pub async fn create_venue_handler(
        state_manager: web::Data<Arc<StoreStateManager>>,
        mut user: LoggedUser, // Authenticate the request
        venue_data: web::Json<CreateVenueRequest>, // Extract JSON request body
    ) -> Result<HttpResponse, ActixError> { // Handler returns Result<HttpResponse, ActixError>
        // Validate the session and get the creator user_id
        let creator_user_id = user.validate(&state_manager).await
            .map_err(|app_err| ErrorInternalServerError(app_err))?; // Convert potential AppError from validate

        let req_data = venue_data.into_inner(); // Get the raw request data

        // 1. Validate and parse incoming data
        if req_data.title.is_empty() {
            return Ok(HttpResponse::BadRequest().json(CreateVenueResponse {
                success: false,
                venue_id: None,
                error_message: Some("Venue title cannot be empty.".to_string()),
            }));
        }

        // Check if description is None OR the string inside is empty
        if req_data.description.as_ref().map_or(true, |s| s.is_empty()) {
            return Ok(HttpResponse::BadRequest().json(CreateVenueResponse {
                success: false,
                venue_id: None,
                error_message: Some("Venue description cannot be empty.".to_string()),
            }));
        }

        // Check if address is None OR the string inside is empty
        if req_data.address.as_ref().map_or(true, |s| s.is_empty()) {
            return Ok(HttpResponse::BadRequest().json(CreateVenueResponse {
                success: false,
                venue_id: None,
                error_message: Some("Venue address cannot be empty.".to_string()),
            }));
        }

        // Check if suburb is None OR the string inside is empty
        if req_data.suburb.as_ref().map_or(true, |s| s.is_empty()) {
            return Ok(HttpResponse::BadRequest().json(CreateVenueResponse {
                success: false,
                venue_id: None,
                error_message: Some("Venue suburb cannot be empty.".to_string()),
            }));
        }

        // Check if postcode is None OR the string inside is empty
        if req_data.postcode.as_ref().map_or(true, |s| s.is_empty()) {
            return Ok(HttpResponse::BadRequest().json(CreateVenueResponse {
                success: false,
                venue_id: None,
                error_message: Some("Venue postcode cannot be empty.".to_string()),
            }));
        }

        // Generate a unique ID for the new venue
        let venue_id = Uuid::new_v4();

        // 2. Call the database function to create the venue
        let create_result: AppResult<()> = state_manager.db.create_new_venue(
            &creator_user_id,
            &venue_id, // Pass the generated venue_id
            &req_data.title,
            &req_data.description,
            &req_data.address,
            &req_data.suburb,
            &req_data.postcode ).await;
        // Handle the result of the database operation
        match create_result {
            Ok(_) => {
                // Venue created successfully
                tracing::info!("Venue {} created successfully by user {}", venue_id, creator_user_id);
                // Return a success response with the newly created venue ID
                Ok(HttpResponse::Ok().json(CreateClassResponse {
                    success: true,
                    class_id: Some(venue_id),
                    error_message: None,
                }))
            }
            Err(app_err) => {
                // Database error occurred during creation
                tracing::error!("Database error creating venue for user {}: {:?}", creator_user_id, app_err);
                // Manually convert AppError to ActixError using ErrorInternalServerError
                Err(ErrorInternalServerError(app_err))
            }
        }
    }
           
    // Get Venue List
    #[get("/api/venue/get_list")]
    pub async fn get_venue_list_handler(
        state_manager: web::Data<Arc<StoreStateManager>>, // State manager for DB access
        _user: LoggedUser, // Require user to be logged in (authentication), but don't need user_id for this list
    ) -> Result<HttpResponse, ActixError> { // Handler returns Result<HttpResponse, ActixError>
        // The LoggedUser extractor handles the authentication check.
        // If authentication fails, Actix Web will return an Unauthorized error
        // before the handler body executes. The _user variable is unused
        // if the user_id isn't needed for filtering *this* specific list endpoint.

        // Call the database function to get venues based on the provided filters
        let venues_result: AppResult<Vec<VenueData>> = state_manager.db.get_venues().await; // Use '?' to propagate AppError from get_classes - OH WAIT, get_classes returns AppResult, need match/map_err

        // Handle the result of the database operation explicitly
        match venues_result {
            Ok(venues) => {
                // Database function succeeded, returns a Vec<ClassData> (could be empty)
                // tracing::info!("Successfully fetched {} venues.", venues.len());
                // Return the vector of ClassData as a JSON array with 200 OK status
                Ok(HttpResponse::Ok().json(venues))
            },
            Err(app_err) => {
                // A database error (AppError) occurred
                tracing::error!("Database error fetching venue list: {:?}", app_err);
                // Convert the AppError into an ActixError representing a 500 Internal Server Error
                Err(ErrorInternalServerError(app_err))
            }
        }
    }


    // Create style
    #[post("/api/style/create")]
    pub async fn create_style_handler(
        state_manager: web::Data<Arc<StoreStateManager>>,
        mut user: LoggedUser, // Authenticate the request
        style_data: web::Json<CreateStyleRequest>, // Extract JSON request body
    ) -> Result<HttpResponse, ActixError> { // Handler returns Result<HttpResponse, ActixError>
        // Validate the session and get the creator user_id
        let creator_user_id = user.validate(&state_manager).await
            .map_err(|app_err| ErrorInternalServerError(app_err))?; // Convert potential AppError from validate

        let req_data = style_data.into_inner(); // Get the raw request data

        // 1. Validate and parse incoming data
        if req_data.title.is_empty() {
            return Ok(HttpResponse::BadRequest().json(CreateStyleResponse {
                success: false,
                style_id: None,
                error_message: Some("Style title cannot be empty.".to_string()),
            }));
        }

        // Check if description is None OR the string inside is empty
        if req_data.description.as_ref().map_or(true, |s| s.is_empty()) {
            return Ok(HttpResponse::BadRequest().json(CreateStyleResponse {
                success: false,
                style_id: None,
                error_message: Some("Style description cannot be empty.".to_string()),
            }));
        }

        // Generate a unique ID for the new style
        let style_id = Uuid::new_v4();

        // 2. Call the database function to create the style
        let create_result: AppResult<()> = state_manager.db.create_style(
            &creator_user_id,
            &style_id, // Pass the generated style_id
            &req_data.title,
            &req_data.description ).await;
        // Handle the result of the database operation
        match create_result {
            Ok(_) => {
                // Style created successfully
                tracing::info!("Style {} created successfully by user {}", style_id, creator_user_id);
                // Return a success response with the newly created style ID
                Ok(HttpResponse::Ok().json(CreateClassResponse {
                    success: true,
                    class_id: Some(style_id),
                    error_message: None,
                }))
            }
            Err(app_err) => {
                // Database error occurred during creation
                tracing::error!("Database error creating style for user {}: {:?}", creator_user_id, app_err);
                // Manually convert App Error to ActixError using ErrorInternalServerError
                Err(ErrorInternalServerError(app_err))
            }
        }
    }

    // Get Style List
    #[get("/api/style/get_list")]
    pub async fn get_style_list_handler(
        state_manager: web::Data<Arc<StoreStateManager>>, // State manager for DB access
        _user: LoggedUser, // Require user to be logged in (authentication), but don't need user_id for this list
    ) -> Result<HttpResponse, ActixError> { // Handler returns Result<HttpResponse, ActixError>
        // The LoggedUser extractor handles the authentication check.
        // If authentication fails, Actix Web will return an Unauthorized error
        // before the handler body executes. The _user variable is unused
        // if the user_id isn't needed for filtering *this* specific list endpoint.

        // Call the database function to get styles based on the provided filters
        let styles_result: AppResult<Vec<StyleData>> = state_manager.db.get_styles().await; // Use '?' to propagate AppError from get_classes - OH WAIT, get_classes returns AppResult, need match/map_err

        // Handle the result of the database operation explicitly
        match styles_result {
            Ok(styles) => {
                // Database function succeeded, returns a Vec<ClassData> (could be empty)
                // tracing::info!("Successfully fetched {} styles.", styles.len());
                // Return the vector of ClassData as a JSON array with 200 OK status
                Ok(HttpResponse::Ok().json(styles))
            },
            Err(app_err) => {
                // A database error (AppError) occurred
                tracing::error!("Database error fetching style list: {:?}", app_err);
                // Convert the AppError into an ActixError representing a 500 Internal Server Error
                Err(ErrorInternalServerError(app_err))
            }
        }
    }


}
