pub mod handlers {
    use actix_web::{post, get, put, web, http::header::{LOCATION, CONTENT_TYPE}, HttpRequest, HttpResponse, cookie::{Cookie, SameSite}};
    use argon2::password_hash;
    // use mma::api::GenericResponse;
    use std::sync::Arc;
    use uuid::Uuid;
    use crate::{api::{GetClassRequest, GetClassResponse}, state::StoreStateManager};
    // use crate::error::AppError;
    use crate::api::{
        LoginRequest, LoginResponse, CreateUserRequest, CreateUserResponse, ContactForm,
        GetUserProfileResponse, UpdateUserProfileRequest, UpdateUserProfileResponse,
        ChangePasswordRequest, ChangePasswordResponse, GetWaiverResponse,
        AcceptWaiverRequest, AcceptWaiverResponse, CreateWaiverResponse, CreateWaiverRequest,  // Re-using or adjusting generic response
        CreateClassRequest, CreateClassResponse, ClassFrequency, ClassFrequencyRequest, 
        ClassData, CreateVenueRequest, CreateVenueResponse, VenueData, CreateStyleRequest, CreateStyleResponse, StyleData,
        ForgottenPasswordRequest, ForgottenPasswordResponse, ResetPasswordQuery, ResetPasswordResponse, ResetPasswordRequest,
        SignupResponse, SignupRequest, VerifyAccountQuery, GetVenueRequest, GetVenueResponse, UpdateClassRequest, ClassFrequencyId,
        GetVenueListResponse, GenericResponse
    };
    use chrono::{NaiveDate, NaiveTime, Utc};
    use bigdecimal::BigDecimal;
    use crate::auth::LoggedUser;
    use crate::db::{verify_password, hash_password};
    use crate::templates::{TemplateCache, get_template_content};
    use actix_web::error::Error as ActixError;
    use crate::error::{AppError, Result as AppResult};
    use actix_web::error::ErrorInternalServerError;
    use crate::email_sender::send_custom_email;
    use urlencoding;

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
    // #[get("/style.css")]
    // pub async fn serve_css(cache: web::Data<TemplateCache>) -> HttpResponse {
    //     match get_template_content(&cache, "style.css") {
    //         Ok(content) => HttpResponse::Ok()
    //             // Set the correct Content-Type for CSS files
    //             .content_type("text/css")
    //             .body(content),
    //         Err(resp) => resp, // Return 404 or other error from get_template_content
    //     }
    // }

    #[get("/")]
    pub async fn home_page(cache: web::Data<TemplateCache>) -> HttpResponse {
        match get_template_content(&cache, "home.html") {
            Ok(content) => HttpResponse::Ok()
                .insert_header((CONTENT_TYPE, "text/html; charset=utf-8"))
                .body(content),
            Err(resp) => resp, // Return the 404 response from the helper
        }
    }

    // #[get("/login")]
    // pub async fn login_signup_page(cache: web::Data<TemplateCache>) -> HttpResponse {
    //      match get_template_content(&cache, "login.html") {
    //         Ok(content) => HttpResponse::Ok()
    //             .insert_header((CONTENT_TYPE, "text/html; charset=utf-8"))
    //             .body(content),
    //         Err(resp) => resp,
    //     }
    // }

    // #[get("/gym-signup")]
    // pub async fn gym_signup_page(cache: web::Data<TemplateCache>) -> HttpResponse {
    //      match get_template_content(&cache, "gym_signup.html") {
    //         Ok(content) => HttpResponse::Ok()
    //             .insert_header((CONTENT_TYPE, "text/html; charset=utf-8"))
    //             .body(content),
    //         Err(resp) => resp,
    //     }
    // }

    // #[get("/contact")]
    // pub async fn contact_page(cache: web::Data<TemplateCache>) -> HttpResponse {
    //      match get_template_content(&cache, "contact.html") {
    //         Ok(content) => HttpResponse::Ok()
    //             .insert_header((CONTENT_TYPE, "text/html; charset=utf-8"))
    //             .body(content),
    //         Err(resp) => resp,
    //     }
    // }

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
            Some(&req.password),
            None,
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
            false
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
            &login_req.email,
            &login_req.password,
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
            &creator_user_id,
            &class_id, // Pass the generated class_id
            &req_data.title,
            &req_data.description,
            &req_data.venue_id,
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


    // --- Class Creation Handler ---
    #[put("/api/class/update")]
    pub async fn update_class_handler(
        state_manager: web::Data<Arc<StoreStateManager>>,
        mut user: LoggedUser, // Authenticate the request
        class_data: web::Json<UpdateClassRequest>, // Extract JSON request body
    ) -> Result<HttpResponse, ActixError> { // Handler returns Result<HttpResponse, ActixError>

        // 1. Validate the session and get the creator user_id
        let creator_user_id = user.validate(&state_manager).await
            .map_err(|app_err| ErrorInternalServerError(app_err))?; // Convert potential AppError from validate

        let req_data = class_data.into_inner(); // Get the raw request data
        let class_id = req_data.class_id; // Use the class_id from the request
        // 2. Validate and parse incoming data
        // You might want more robust validation here (e.g., check min/max values, non-empty strings)

        // Generate a unique ID for the new class

        // Parse the frequency dates and times from strings
        let mut parsed_frequency = Vec::new();
        for freq_req in req_data.frequency {
            let class_freqency_id = match freq_req.class_frequency_id {
                Some(id) => id,
                None => {
                    Uuid::new_v4() // Generate a new ID if not provided
                }
            };

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
            parsed_frequency.push(ClassFrequencyId { // Use the struct defined in db.rs
                class_frequency_id: class_freqency_id,
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
        let create_result: AppResult<()> = state_manager.db.update_class(
            &creator_user_id,
            &class_id, // Pass the generated class_id
            &req_data.title,
            &req_data.description,
            &req_data.venue_id,
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
                tracing::info!("Class {} updated successfully by user {}", class_id, creator_user_id);
                // Return a success response with the newly created class ID
                Ok(HttpResponse::Ok().json(CreateClassResponse {
                    success: true,
                    class_id: Some(class_id),
                    error_message: None,
                }))
            }
            Err(app_err) => {
                // Database error occurred during creation
                tracing::error!("Database error updating class for user {}: {:?}", creator_user_id, app_err);
                // Manually convert AppError to ActixError using ErrorInternalServerError
                Err(ErrorInternalServerError(app_err))
            }
        }
    }


    // --- Get Class List Handler ---
    #[get("/api/class/get_list")] // Define the GET endpoint path
    pub async fn get_class_list_handler(
        state_manager: web::Data<Arc<StoreStateManager>>, // State manager for DB access
        mut user: LoggedUser, // Require user to be logged in (authentication), but don't need user_id for this list
        // query_params: Query<GetClassesQueryParams>, // Extract query parameters from the URL
    ) -> Result<HttpResponse, ActixError> { // Handler returns Result<HttpResponse, ActixError>

        let auth_user_id = user.validate(&state_manager).await
            .map_err(|app_err| ErrorInternalServerError(app_err))?; // Convert potential AppError from validate

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
    

    // --- Get Class List Handler ---
    #[post("/api/class/get")] // Define the GET endpoint path
    pub async fn get_class_handler(
        state_manager: web::Data<Arc<StoreStateManager>>, // State manager for DB access
        mut user: LoggedUser, // Require user to be logged in (authentication), but don't need user_id for this list
        req: web::Json<GetClassRequest>, // Extract query parameters from the URL
    ) -> Result<HttpResponse, ActixError> { // Handler returns Result<HttpResponse, ActixError>

        let auth_user_id = user.validate(&state_manager).await
            .map_err(|app_err| ErrorInternalServerError(app_err))?; // Convert potential AppError from validate

        let class_id = req.class_id; // Extract class_id from query parameters

        // Call the database function to get classes based on the provided filters
        let class_result: AppResult<Option<ClassData>> = state_manager.db.get_class(&class_id).await; // Use '?' to propagate AppError from get_classes - OH WAIT, get_classes returns AppResult, need match/map_err

        // Handle the result of the database operation explicitly
        match class_result {
            Ok(class) => {
                // Database function succeeded, returns a Vec<ClassData> (could be empty)
                // tracing::info!("Successfully fetched {} classes.", classes.len());
                // Return the vector of ClassData as a JSON array with 200 OK status
                match class {
                    Some(class_data) => {
                        Ok(HttpResponse::Ok().json(GetClassResponse {
                            success: true,
                            class: Some(class_data),
                            error_message: None,
                        }))
                    },
                    None => {
                        Ok(HttpResponse::Ok().json(GetClassResponse {
                            success: false,
                            class: None,
                            error_message: Some("Class does not exist".to_string()),
                        }))
                    }
                }

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
            &req_data.state,
            &req_data.country,
            &req_data.postcode,
            &req_data.latitude, // Pass Option<&Decimal>
            &req_data.longitude, // Pass Option<&Decimal>
            &req_data.contact_phone,
         ).await;
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
           

    // Handler to update an existing venue
    #[put("/api/venue/update")] // Use PUT method and include venue_id in the path
    pub async fn update_venue_handler(
        state_manager: web::Data<Arc<StoreStateManager>>, // State manager for DB access
        mut user: LoggedUser, // Authenticate the request
        venue_data: web::Json<VenueData>, // Extract JSON request body
    ) -> Result<HttpResponse, ActixError> { // Handler returns ActixResult<HttpResponse>
        let venue_id = venue_data.venue_id; // Extract the UUID from the path

        // 1. Authenticate and authorize the user
        let user_id = user.validate(&state_manager).await
            .map_err(|e| {
                tracing::error!("Authentication error during venue update: {:?}", e);
                // Consider mapping specific AppErrors to different ActixErrors (e.g., Unauthorized)
                ErrorInternalServerError("Authentication failed") // Generic error for now
            })?;

        // Implement authorization check here. For example, only admins can update venues.
        // You'll need a way to get the user's role or permissions.
        // Example:
        // let user_role = state_manager.db.get_user_role(&user_id).await?; // Assuming this function exists
        // if user_role != "admin" { // Or check specific permission flag
        //     tracing::warn!("User {} attempted to update venue {} without sufficient permissions.", user_id, venue_id);
        //     return Err(actix_web::error::ErrorForbidden("You do not have permission to update venues."));
        // }
        tracing::info!("User {} is attempting to update venue {}", user_id, venue_id);


        let req_data = venue_data.into_inner(); // Get the raw request data

        // 2. Validate incoming data from the request body
        // Title is required for an update, just like create
        if req_data.title.trim().is_empty() { // Trim whitespace before checking for empty
            tracing::warn!("Attempted to update venue {} with empty title.", venue_id);
            return Ok(HttpResponse::BadRequest().json(GenericResponse {
                    success: false,
                    message: None,
                    error_message: Some("Venue title cannot be empty.".to_string()),
                }));
        }

        // Convert optional empty strings to None for Option<String> fields
        // let description = req_data.description.filter(|s| !s.trim().is_empty());
        // let address = req_data.address.filter(|s| !s.trim().is_empty());
        // let suburb = req_data.suburb.filter(|s| !s.trim().is_empty());
        // let state = req_data.state.filter(|s| !s.trim().is_empty());
        // let postcode = req_data.postcode.filter(|s| !s.trim().is_empty());
        // let country = req_data.country.filter(|s| !s.trim().is_empty());
        // let contact_phone = req_data.contact_phone.filter(|s| !s.trim().is_empty());

        // Parse optional latitude and longitude (assuming frontend sends f64 if present)
        // let latitude = req_data.latitude;
        // let longitude = req_data.longitude;


        // 3. Call the database function to update the venue
        // Assuming your db.rs has an update_venue function with a signature like:
        // pub async fn update_venue(&self, venue_id: &Uuid, title: &str, description: Option<&str>, ...) -> AppResult<bool>;
        // The boolean return could indicate if a venue was found and updated (false if not found)
        let update_result: AppResult<bool> = state_manager.db.update_venue(
            &venue_id, // Pass the venue_id from the path
            &req_data.title, // Pass the trimmed title
            &req_data.description, // Pass Option<&str>
            &req_data.address,
            &req_data.suburb,
            &req_data.state,
            &req_data.country,
            &req_data.postcode,
            &req_data.latitude, // Pass Option<&Decimal>
            &req_data.longitude, // Pass Option<&Decimal>
            &req_data.contact_phone,
            // Pass other fields...
        ).await;


        // 4. Handle the result of the database operation
        match update_result {
            Ok(true) => {
                // Database function succeeded and the venue was found and updated
                tracing::info!("Venue {} updated successfully by user {}", venue_id, user_id);
                // Return a success response
                Ok(HttpResponse::Ok().json(GenericResponse {
                    success: true,
                    message: Some("Venue updated successfully.".to_string()),
                    error_message: None,
                }))
            },
            Ok(false) => {
                // Database function succeeded but the venue was NOT found with that ID
                tracing::warn!("Attempted to update non-existent venue: {}", venue_id);
                // Err(ErrorNotFound(format!("Venue with ID {} not found", venue_id)))
                Ok(HttpResponse::Ok().json(GenericResponse {
                    success: false,
                    message: None,
                    error_message: Some("Venue does not exist.".to_string()),
                }))

            }
            Err(app_err) => {
                // Database error occurred during update
                tracing::error!("Database error updating venue {} for user {}: {:?}", venue_id, user_id, app_err);
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
                Ok(HttpResponse::Ok().json(GetVenueListResponse{
                    success: true,
                    error_message: None,
                    venues: Some(venues)
                    }))
            },
            Err(app_err) => {
                // A database error (AppError) occurred
                tracing::error!("Database error fetching venue list: {:?}", app_err);
                // Convert the AppError into an ActixError representing a 500 Internal Server Error
                Err(ErrorInternalServerError(app_err))
            }
        }
    }


    // Handler to get a single venue by ID
    #[post("/api/venue/get")]
    pub async fn get_venue_handler(
        state_manager: web::Data<Arc<StoreStateManager>>,
        mut user: LoggedUser, // Authenticate the request
        req: web::Json<GetVenueRequest>, // Extract JSON request body
    ) -> Result<HttpResponse, ActixError> { // Handler returns ActixResult<HttpResponse>
        // The LoggedUser extractor handles the authentication check.
        // If authentication fails, Actix Web will return an Unauthorized error (401)
        // before the handler body executes.

        let creator_user_id = user.validate(&state_manager).await
            .map_err(|app_err| ErrorInternalServerError(app_err))?; // Convert potential AppError from validate

        let venue_id = req.venue_id; // Extract the UUID from the path

        // tracing::info!("Fetching venue with ID: {}", venue_id);

        // Call the database function to get the venue by ID
        let venue_result: AppResult<Option<VenueData>> = state_manager.db.get_venue(&venue_id).await;

        // Handle the result of the database operation
        match venue_result {
            Ok(Some(venue)) => {
                // Database function succeeded and found the venue
                tracing::info!("Successfully fetched venue: {}", venue_id);
                // Return the VenueData as JSON with 200 OK status
                Ok(HttpResponse::Ok().json(GetVenueResponse {
                    success: true,
                    venue: Some(venue),
                    error_message: None,
                }))
            },
            Ok(None) => {
                // Database function succeeded but the venue was not found
                // tracing::warn!("Venue not found with ID: {}", venue_id);
                // Return a 404 Not Found error
                // Err(ErrorNotFound(format!("Venue with ID {} not found", venue_id)))
                Ok(HttpResponse::Ok().json(GetVenueResponse {
                    success: false,
                    venue: None,
                    error_message: Some("No venue found with this ID.".to_string()),
                }))

            },
            Err(app_err) => {
                // A database error (AppError) occurred
                tracing::error!("Database error fetching venue {}: {:?}", venue_id, app_err);
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


    #[post("/api/user/forgotten_password")]
    pub async fn handle_forgotten_password(
        req: web::Json<ForgottenPasswordRequest>,
        state_manager: web::Data<Arc<StoreStateManager>>, // State manager for DB access
    ) -> Result<HttpResponse, ActixError> {
        let email = req.email.clone();
        
        // Check if the email exists in the database
        // We need to get the full user object to get the user_id
        let user_opt = match state_manager.db.get_user_by_email(&email).await {
            Ok(user) => user,
            Err(e) => {
                tracing::error!("Database error when looking up user by email: {}", e);
                // Still continue with the process to avoid leaking info
                None
            }
        };
        
        // If the user exists, send them a password reset email
        if let Some((user_id, _)) = user_opt {
            // Generate a reset code
            let reset_code = uuid::Uuid::new_v4().to_string();
            
            // Store the code in the database with a 4-hour expiry
            match state_manager.db.add_forgotten_password_code(&email, user_id, &reset_code, 4).await {
                Ok(_) => {
                    tracing::info!("Added password reset code for user: {}", user_id);
                    
                    // Generate the reset URL with email and code
                    let reset_url = format!(
                        "https://narsue.com/reset_password?email={}&code={}", 
                        urlencoding::encode(&email), 
                        reset_code
                    );
                    
                    // Create personalized email if we have the user's name
                    // let greeting = if !user.first_name.is_empty() {
                    //     format!("Hello {},", user.first_name)
                    // } else {
                    let greeting = "Hello,".to_string();
                    // };
                    
                    let html_body = format!(
                        r#"<html>
                        <body>
                            <h1>Password Reset Request</h1>
                            <p>{}</p>
                            <p>We received a request to reset your password. If you didn't make this request, you can ignore this email.</p>
                            <p>To reset your password, please click the link below:</p>
                            <p><a href="{}">Reset Password</a></p>
                            <p>This link will expire in 4 hours.</p>
                            <p>Regards,<br>MMA Gym Management</p>
                        </body>
                        </html>"#,
                        greeting,
                        reset_url
                    );
                    
                    // Send the email
                    match send_custom_email(
                        "narsue@narsue.com", // Use your system email address
                        &email,
                        &html_body,
                        "Password Reset Instructions"
                    ).await {
                        Ok(true) => {
                            tracing::info!("Password reset email sent successfully to {}", email);
                        },
                        Ok(false) => {
                            tracing::error!("Failed to send password reset email to {}", email);
                            // Continue anyway to avoid leaking information
                        },
                        Err(e) => {
                            tracing::error!("Error sending password reset email: {}", e);
                            // Continue anyway to avoid leaking information
                        }
                    }
                },
                Err(e) => {
                    tracing::error!("Failed to store password reset code: {}", e);
                    // Continue anyway to avoid leaking information
                }
            }
        } else {
            // Log that no user was found, but don't expose this in the response
            tracing::info!("Password reset requested for non-existent email: {}", email);
        }
        
        // Always return success regardless of whether the email exists
        // This prevents user enumeration attacks
        Ok(HttpResponse::Ok().json(ForgottenPasswordResponse {
            success: true,
            message: Some(String::from("If your email address exists in our system, you will receive a password reset link shortly.")),
            error_message: None,
        }))
    }


    #[get("/reset_password")]
    pub async fn serve_reset_password_page(
        cache: web::Data<TemplateCache>,
        query: web::Query<ResetPasswordQuery>,
    ) -> Result<HttpResponse, ActixError> {
        // Here we don't validate the code yet - that happens on form submission
        // We just serve the HTML page with the email and code embedded
        match get_template_content(&cache, "forgotten_password.html") {
            Ok(content) => {
                let html = content
                    .replace("{{EMAIL}}", &query.email)
                    .replace("{{CODE}}", &query.code);

                Ok(HttpResponse::Ok()
                    .insert_header((CONTENT_TYPE, "text/html; charset=utf-8"))
                    .body(html))
            },
            Err(resp) => Ok(resp), // Return the 404 response from the helper
        }
    }

    
    #[post("/api/user/reset_password")]
    pub async fn handle_reset_password(
        req: web::Json<ResetPasswordRequest>,
        state_manager: web::Data<Arc<StoreStateManager>>,
    ) -> Result<HttpResponse, ActixError> {
        let email = &req.email;
        let code = &req.code;
        let new_password = &req.new_password;
        
        // Validate password requirements on server side too
        if new_password.len() < 8 {
            return Ok(HttpResponse::BadRequest().json(ResetPasswordResponse {
                success: false,
                message: None,
                error_message: Some("Password must be at least 8 characters long.".to_string()),
            }));
        }
        
        // Check if the code is valid and mark it as used
        match state_manager.db.check_and_use_forgotten_password_code(email, code).await {
            Ok(Some(user_id)) => {
                // Hash the new password
                let new_password_hash = match hash_password(new_password) {
                    Ok(hash) => hash,
                    Err(e) => {
                        tracing::error!("Error hashing new password: {:?}", e);
                        return Ok(HttpResponse::InternalServerError().json(ResetPasswordResponse {
                            success: false,
                            message: None,
                            error_message: Some("Server error processing your request.".to_string()),
                        }));
                    }
                };
                
                // Update the password in the database
                match state_manager.db.update_password_hash(user_id, new_password_hash).await {
                    Ok(_) => {
                        tracing::info!("Password successfully reset for user ID: {}", user_id);
                        
    
                        // Create a session for the user (auto-login)
                        // Get the request info for session tracking
                        // let ip = "0.0.0.0".to_string(); // In a real app, get this from the request
                        // let user_agent = "Reset Password Flow".to_string(); // In a real app, get this from the request
                        let ip = None; // In a real app, get this from the request
                        let user_agent = None; // In a real app, get this from the request
                        match state_manager.db.create_session(
                            &user_id,
                            ip,
                            user_agent,
                            24
                        ).await  {


                        // match state_manager.create_session(user_id, ip, user_agent).await {
                            Ok(session_token) => {
                                // Set session cookies
                                let cookie = Cookie::build("session", session_token.clone())
                                    .path("/")
                                    .secure(true)
                                    .http_only(true)
                                    .same_site(SameSite::Strict)
                                    .max_age(time::Duration::hours(24))
                                    .finish();
                                
                                let user_id_cookie = Cookie::build("user_id", user_id.to_string())
                                    .path("/")
                                    .secure(true)
                                    .http_only(false)
                                    .same_site(SameSite::Strict)
                                    .max_age(time::Duration::hours(24))
                                    .finish();
                                    
                                // Return success with cookies set
                                Ok(HttpResponse::Ok()
                                    .cookie(cookie)
                                    .cookie(user_id_cookie)
                                    .json(ResetPasswordResponse {
                                        success: true,
                                        message: Some("Your password has been reset successfully.".to_string()),
                                        error_message: None,
                                    }))
                            },
                            Err(e) => {
                                tracing::error!("Failed to create session after password reset: {:?}", e);
                                // Still return success for the password reset, even if session creation failed
                                Ok(HttpResponse::Ok().json(ResetPasswordResponse {
                                    success: true,
                                    message: Some("Your password has been reset successfully. Please log in with your new password.".to_string()),
                                    error_message: None,
                                }))
                            }
                        }
                    },
                    Err(e) => {
                        tracing::error!("Failed to update password: {:?}", e);
                        Ok(HttpResponse::InternalServerError().json(ResetPasswordResponse {
                            success: false,
                            message: None,
                            error_message: Some("Failed to update password. Please try again.".to_string()),
                        }))
                    }
                }
            },
            Ok(None) => {
                tracing::warn!("Invalid or expired reset code for email: {}", email);
                Ok(HttpResponse::BadRequest().json(ResetPasswordResponse {
                    success: false,
                    message: None,
                    error_message: Some("Invalid or expired password reset link. Please request a new password reset.".to_string()),
                }))
            },
            Err(e) => {
                tracing::error!("Database error checking reset code: {:?}", e);
                Ok(HttpResponse::InternalServerError().json(ResetPasswordResponse {
                    success: false,
                    message: None,
                    error_message: Some("Server error processing your request.".to_string()),
                }))
            }
        }
    }


    #[post("/api/user/signup")]
    pub async fn handle_signup(
        req: web::Json<SignupRequest>,
        state_manager: web::Data<Arc<StoreStateManager>>, // State manager for DB access
    ) -> Result<HttpResponse, ActixError> {
        let email = req.email.clone();
        let first_name = req.first_name.clone();
        let surname = req.surname.clone();
        
        // Check if the email exists in the database
        let user_exists = match state_manager.db.get_user_by_email(&email).await {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(e) => {
                tracing::error!("Database error when looking up user by email: {}", e);
                return Ok(HttpResponse::InternalServerError().json(SignupResponse {
                    success: false,
                    message: None,
                    error_message: Some(String::from("An error occurred while processing your request.")),
                }));
            }
        };
        
        if user_exists {
            // User already exists, send them an email about it
            let html_body = format!(
                r#"<html>
                <body>
                    <h1>Account Already Exists</h1>
                    <p>Hello,</p>
                    <p>We received a request to create an account with this email address, but there's already an account registered with {}.</p>
                    <p>If you've forgotten your password, you can use the password reset feature at <a href="https://narsue.com/login">our login page</a>.</p>
                    <p>If you didn't request this registration, you can safely ignore this email.</p>
                    <p>Regards,<br>MMA Gym Management</p>
                </body>
                </html>"#,
                email
            );
            
            // Send the email
            match send_custom_email(
                "narsue@narsue.com", // Use your system email address
                &email,
                &html_body,
                "Account Already Exists"
            ).await {
                Ok(true) => {
                    tracing::info!("Account already exists email sent to {}", email);
                },
                Ok(false) => {
                    tracing::error!("Failed to send account exists email to {}", email);
                },
                Err(e) => {
                    tracing::error!("Error sending account exists email: {}", e);
                }
            }
            
            // Return success message to avoid user enumeration
            return Ok(HttpResponse::Ok().json(SignupResponse {
                success: true,
                message: Some(String::from("If your email is not already registered, you will receive a verification link shortly.")),
                error_message: None,
            }));
        }
        
        // Generate a verification code
        let verification_code = uuid::Uuid::new_v4().to_string();
        
        let password_hash = match hash_password(&req.password) {
            Ok(hash) => hash,
            Err(e) => {
                tracing::error!("Error hashing password: {:?}", e);
                return Ok(HttpResponse::InternalServerError().json(SignupResponse {
                    success: false,
                    message: None,
                    error_message: Some(String::from("An error occurred while processing your request.")),
                }));
            }
        };

        // Store the verification code in the database with a 24-hour expiry
        match state_manager.db.add_sign_up_invite_code(&email, &verification_code, 24, &first_name, &surname, &password_hash).await {
            Ok(_) => {
                tracing::info!("Added verification code for new user: {}", email);
                
                // Generate the verification URL
                let verification_url = format!(
                    "https://narsue.com/verify-account?email={}&code={}", 
                    urlencoding::encode(&email), 
                    verification_code
                );
                
                // Create personalized email with the user's name
                let greeting = format!("Hello {},", first_name);
                
                let html_body = format!(
                    r#"<html>
                    <body>
                        <h1>Verify Your Email Address</h1>
                        <p>{}</p>
                        <p>Thank you for registering with MMA Gym Management. To complete your registration, please verify your email address by clicking the link below:</p>
                        <p><a href="{}">Verify Email Address</a></p>
                        <p>This link will expire in 24 hours.</p>
                        <p>If you didn't create this account, you can safely ignore this email.</p>
                        <p>Regards,<br>MMA Gym Management</p>
                    </body>
                    </html>"#,
                    greeting,
                    verification_url
                );
                
                // Send the verification email
                match send_custom_email(
                    "narsue@narsue.com", // Use your system email address
                    &email,
                    &html_body,
                    "Verify Your Email Address"
                ).await {
                    Ok(true) => {
                        tracing::info!("Verification email sent successfully to {}", email);
                        
                        // Store user info temporarily or hash the password now
                        // Note: You would typically want to store this information somewhere temporary
                        // or securely until the user verifies their email
                        
                        // For now, we'll just return success
                        return Ok(HttpResponse::Ok().json(SignupResponse {
                            success: true,
                            message: Some(String::from("Please check your email to verify your account.")),
                            error_message: None,
                        }));
                    },
                    Ok(false) => {
                        tracing::error!("Failed to send verification email to {}", email);
                        return Ok(HttpResponse::InternalServerError().json(SignupResponse {
                            success: false,
                            message: None,
                            error_message: Some(String::from("Failed to send verification email. Please try again later.")),
                        }));
                    },
                    Err(e) => {
                        tracing::error!("Error sending verification email: {}", e);
                        return Ok(HttpResponse::InternalServerError().json(SignupResponse {
                            success: false,
                            message: None,
                            error_message: Some(String::from("An error occurred while sending verification email. Please try again later.")),
                        }));
                    }
                }
            },
            Err(e) => {
                tracing::error!("Failed to store verification code: {}", e);
                return Ok(HttpResponse::InternalServerError().json(SignupResponse {
                    success: false,
                    message: None,
                    error_message: Some(String::from("An error occurred while processing your request. Please try again later.")),
                }));
            }
        }
    }


    // Handler to verify account and create user
    #[get("/verify-account")]
    pub async fn verify_account(
        query: web::Query<VerifyAccountQuery>,
        state_manager: web::Data<Arc<StoreStateManager>>,
    ) -> Result<HttpResponse, ActixError> { // Changed return type to ActixResult
        let email = query.email.clone();
        let code = query.code.clone();
    
        // Validate the verification code and retrieve user info
        match state_manager.db.check_and_use_sign_up_invite_code(&email, &code).await {
            Ok((valid,first_name, surname, password_hash)) => {
                if !valid {
                    // Invalid or expired code
                    tracing::warn!("Invalid or expired verification code for email: {}", email);
                    return Ok(HttpResponse::BadRequest().body("Your verification link is invalid, expired, or has already been used. Please request a new one."));
                }
                let password_hash = match password_hash {
                    Some(hash) => hash,
                    None => {
                        tracing::error!("No password hash found for email: {}", email);
                        return Ok(HttpResponse::InternalServerError().body("An error occurred while processing your request. Please try again later."));
                    }
                };
                let first_name = match first_name {
                    Some(name) => name,
                    None => {
                        tracing::error!("No first name found for email: {}", email);
                        return Ok(HttpResponse::InternalServerError().body("An error occurred while processing your request. Please try again later."));
                    }
                };
                let surname = match surname {
                    Some(name) => name,
                    None => {
                        tracing::error!("No surname found for email: {}", email);
                        return Ok(HttpResponse::InternalServerError().body("An error occurred while processing your request. Please try again later."));
                    }
                };

                // Code is valid, and we have the user's info
                tracing::info!("Verification code is valid for email: {}", email);
    
                // Create the user
                let result = state_manager.db.create_user(
                    &email,
                    None, // No raw password needed as we have the hash
                    Some(&password_hash), // Use the stored password hash
                    &first_name,
                    &surname,
                    None, // gender
                    None, // phone
                    None, // dob
                    None, // address
                    None, // suburb
                    None, // emergency_name
                    None, // emergency_relationship
                    None, // emergency_phone
                    None, // emergency_medical
                    true
                ).await;
    
                match result {
                    Ok(user_id) => {
                        tracing::info!("User created successfully with ID: {}", user_id);
    
                        // Create a session for the new user
                        let ip = None; // In a real app, get this from the request
                        let user_agent = None; // In a real app, get this from the request
    
                        match state_manager.db.create_session(
                            &user_id,
                            ip,
                            user_agent,
                            24 // Session expiry in hours
                        ).await {
                            Ok(session_token) => {
                                // Set session cookies
                                let cookie = Cookie::build("session", session_token.clone())
                                    .path("/")
                                    .secure(true)
                                    .http_only(true)
                                    .same_site(SameSite::Strict)
                                    .max_age(time::Duration::hours(24))
                                    .finish();
    
                                // Note: Storing user_id in a non-http_only cookie might be risky
                                // Consider alternative ways to identify the logged-in user client-side
                                let user_id_cookie = Cookie::build("user_id", user_id.to_string())
                                    .path("/")
                                    .secure(true)
                                    .http_only(false)
                                    .same_site(SameSite::Strict)
                                    .max_age(time::Duration::hours(24))
                                    .finish();
    
                                // Redirect to the success page
                                Ok(HttpResponse::Found()
                                    .append_header((LOCATION, "/signup-success"))
                                    .cookie(cookie)
                                    .cookie(user_id_cookie)
                                    .finish())
                            },
                            Err(e) => {
                                tracing::error!("Failed to create session after verification: {:?}", e);
                                Ok(HttpResponse::InternalServerError().body("Failed to create session after verification. Please try again later."))
                            }
                        }
                    },
                    Err(e) => {
                        tracing::error!("Failed to create user after verification: {:?}", e);
                        // More specific error handling based on AppError variant could be added
                        Ok(HttpResponse::InternalServerError().body("Failed to create your account. Please try again later."))
                    }
                }
            },
            // Ok(None) => {
            //     // Invalid or expired code or user info not found
            //     tracing::warn!("Invalid, expired, or used verification code for email: {}", email);
            //     Ok(HttpResponse::BadRequest().body("Your verification link is invalid, expired, or has already been used. Please request a new one."))
            // },
            Err(e) => {
                tracing::error!("Error checking verification code: {:?}", e);
                Ok(HttpResponse::InternalServerError().body("An error occurred while verifying your account. Please try again later."))
            }
        }
    }


    #[get("/signup-success")]
    pub async fn signup_success(cache: web::Data<TemplateCache>) -> HttpResponse {
         match get_template_content(&cache, "signup-success.html") {
            Ok(content) => HttpResponse::Ok()
                .insert_header((CONTENT_TYPE, "text/html; charset=utf-8"))
                .body(content),
            Err(resp) => resp,
        }
    }


}
