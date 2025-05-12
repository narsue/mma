mod api;
mod db;
mod error;
mod models;
mod processor;
mod state;
mod server;
mod auth;
mod templates;

use std::sync::Arc;
use actix_web::{
    web, App, HttpServer,
};
use db::ScyllaConnector;
use state::StoreStateManager;
use server::handlers;
use actix_web::middleware::Logger; // Correct import for Logger
use templates::{load_templates, watch_templates, TemplateCache};

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    tracing::info!("Starting MMA Node");
    
    // Initialize database connection
    let db = Arc::new(ScyllaConnector::new(&["127.0.0.1:9042"]).await?);
    db.init_schema().await?;
    
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
    
    tracing::info!("Starting HTTP server on 127.0.0.1:8080");
    let server = HttpServer::new(move || {
        App::new()
            .app_data(processor_data.clone())
            .app_data(template_data.clone())
            .wrap(Logger::default())

            // --- Serve CSS from Cache ---
            .service(handlers::serve_css)

            // --- Page Routes ---
            .service(handlers::home_page)
            .service(handlers::login_signup_page)
            .service(handlers::gym_signup_page)
            .service(handlers::contact_page)
            .service(handlers::contact_submit) // POST handler for the form

            // Public routes
            .service(handlers::user_login)

            // Protected routes
            .service(handlers::portal_page)
            .service(handlers::user_logout)
            .service(handlers::user_profile)
            .service(handlers::create_user)

            .service(handlers::get_user_profile_data)
            .service(handlers::update_user_profile)
            .service(handlers::change_password)

    })
    .bind("127.0.0.1:8080")?
    .run();
    
    // Wait for server to finish
    server.await?;
    
    Ok(())
}
