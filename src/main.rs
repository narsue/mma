mod api;
mod db;
mod error;
mod models;
mod processor;
mod state;
mod server;
mod auth;
mod templates;
mod email_sender;

use email_sender::send_custom_email;

use std::sync::Arc;
use actix_web::{
    web, App, HttpServer,
};
use db::ScyllaConnector;
use state::StoreStateManager;
use server::handlers;
use actix_web::middleware::Logger; // Correct import for Logger
use templates::{load_templates, watch_templates};

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    tracing::info!("Starting MMA Node");
    

    // let result = send_custom_email(
    //     "narsue@narsue.com",
    //     "narsue@narsue.com",
    //     "<html><body><h1>Hello World</h1><p>This is a test email.</p></body></html>",
    //     "Test Email"
    // ).await;
    
    // match result {
    //     Ok(true) => println!("Email sent successfully!"),
    //     Ok(false) => println!("Failed to send email but no error was thrown"),
    //     Err(e) => println!("Error sending email: {}", e),
    // }


    // Initialize database connection
    let db = Arc::new(ScyllaConnector::new(&["127.0.0.1:9042"]).await?);
    // db.init_schema().await?;
    
    // --- Load Templates ---
    let template_cache = load_templates()?; // Load initially, panics on error here
    let template_cache_clone = template_cache.clone(); // Clone Arc for the watcher task

    // --- Spawn Template Watcher Task ---
    tokio::spawn(async move {
        if let Err(e) = watch_templates(template_cache_clone).await {
            tracing::error!("Template watcher failed: {}", e);
        }
    });

    // Initialize state manager
    let state_manager = Arc::new(StoreStateManager::new(db));
    
    // Start HTTP server
    let processor_data = web::Data::new(state_manager.clone());
    let template_data = web::Data::new(template_cache);
    
    tracing::info!("Starting HTTP server on 127.0.0.1:1227");
    let server = HttpServer::new(move || {
        App::new()
            .app_data(processor_data.clone())
            .app_data(template_data.clone())
            .wrap(Logger::default())

            // --- Serve CSS from Cache ---
            // .service(handlers::serve_css)

            // --- Page Routes ---
            .service(handlers::home_page)
            // .service(handlers::login_signup_page)
            // .service(handlers::gym_signup_page)
            // .service(handlers::contact_page)
            .service(handlers::contact_submit) // POST handler for the form

            // Public routes
            .service(handlers::user_login)

            // Protected routes
            .service(handlers::portal_page)
            .service(handlers::user_logout)
            .service(handlers::user_profile)
            .service(handlers::create_user)
            .service(handlers::serve_reset_password_page)
            .service(handlers::handle_forgotten_password)
            .service(handlers::handle_reset_password)
            .service(handlers::signup_success)
            .service(handlers::verify_account)
            .service(handlers::handle_signup)

            .service(handlers::get_user_profile_data)
            .service(handlers::update_user_profile)
            .service(handlers::change_password)
            .service(handlers::get_latest_waiver)
            .service(handlers::accept_waiver_handler)
            .service(handlers::create_waiver_handler)

            // Class routes
            .service(handlers::create_class_handler)
            .service(handlers::get_class_list_handler)
            .service(handlers::get_class_handler)

            // Venue routes
            .service(handlers::create_venue_handler)
            .service(handlers::get_venue_list_handler)
            .service(handlers::get_venue_handler)

            // Style routes
            .service(handlers::create_style_handler)
            .service(handlers::get_style_list_handler)
            
    })
    .bind("127.0.0.1:1227")?
    .run();
    
    // Wait for server to finish
    server.await?;
    
    Ok(())
}
