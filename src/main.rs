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
mod stripe_client;
mod db_migrate;
mod payment_plan;
use db_migrate::MigrationTool;

use email_sender::send_custom_email;
use stripe_client::StripeClient;
use std::sync::Arc;
use actix_web::{
    web, App, HttpServer,
};
use db::ScyllaConnector;
use state::StoreStateManager;
use server::handlers;
use actix_web::middleware::Logger; // Correct import for Logger
use templates::{load_templates, watch_templates};
use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::{self, format::FormatEvent, format::FormatFields};
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use tracing_subscriber::registry::LookupSpan;
use std::fmt::Write;
use ansi_term::Colour;

struct CustomFormatter;

impl<S, N> FormatEvent<S, N> for CustomFormatter
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &fmt::FmtContext<'_, S, N>,
        mut writer: fmt::format::Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        let meta = event.metadata();
        // Apply color based on log level
        let level_str = match *meta.level() {
            tracing::Level::ERROR => Colour::Red.paint("[ERROR]"),
            tracing::Level::WARN => Colour::Yellow.paint("[WARN]"),
            tracing::Level::INFO => Colour::Green.paint("[INFO]"),
            tracing::Level::DEBUG => Colour::Blue.paint("[DEBUG]"),
            tracing::Level::TRACE => Colour::Purple.paint("[TRACE]"),
        };
        write!(writer, "{} ", level_str)?;

        if let Some(file) = meta.file() {
            if file.starts_with("src/") && file != "src/error.rs"  {
                if let Some(line) = meta.line() {
                    write!(writer, "{}:{} ", file, line)?;
                } else {
                    write!(writer, "{} ", file)?;
                }
            }
        }

        ctx.format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}


#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_ansi(true) // ✅ Enable ANSI colors
        .event_format(CustomFormatter)
        .init();

    tracing::info!("Starting MMA Node");

    // Check local .env file for development mode
    dotenv::dotenv().ok(); // Load environment variables from .env file if it exists

// Read port from environment variable, default to 1227
    let port: u16 = std::env::var("APP_PORT")
        .unwrap_or_else(|_| "1227".to_string())
        .parse::<u16>()
        .expect("APP_PORT must be a valid port number");

    let dev_mode = std::env::var("DEV_MODE").is_ok();
    if dev_mode {
        tracing::info!("Running in development mode");
    } else {
        tracing::info!("Running in production mode");
    }

    // Initialize database connection
    let db = Arc::new(ScyllaConnector::new(&["127.0.0.1:9042"], dev_mode).await?);
    // db.init_schema().await?;
    // Note: Stripe clients are now created per-school as needed, no global client required

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
    
    tracing::info!("Starting HTTP server on 127.0.0.1:{}", port);
    let server = HttpServer::new(move || {
        App::new()
            .app_data(processor_data.clone())
            .app_data(template_data.clone())
            .wrap(Logger::default())

            // --- Serve CSS from Cache ---
            // .service(handlers::serve_css)

            // Server info
            .service(handlers::get_version)
            .service(handlers::health)

            
            // --- Page Routes ---
            .service(handlers::home_page)
            // .service(handlers::login_signup_page)
            // .service(handlers::gym_signup_page)
            // .service(handlers::contact_page)
            .service(handlers::contact_submit) // POST handler for the form

            // Public routes
            .service(handlers::user_login)

            // Protected routes - user authentication required
            .service(handlers::portal_page)
            .service(handlers::kiosk_page)
            .service(handlers::user_logout)
            .service(handlers::user_profile)
            .service(handlers::create_user)
            .service(handlers::serve_reset_password_page)
            .service(handlers::handle_forgotten_password)
            .service(handlers::handle_reset_password)
            .service(handlers::signup_success)
            .service(handlers::verify_account)
            .service(handlers::handle_signup)
            .service(handlers::refresh_session_handler)

            .service(handlers::get_user_profile_data)
            .service(handlers::update_user_profile)
            .service(handlers::change_password)
            .service(handlers::get_user_purchasable_payment_plans_handler)
            .service(handlers::get_payment_plans_handler)
            .service(handlers::user_subscribe_payment_plan)
            .service(handlers::change_subscribe_user_payment_plan)
            .service(handlers::get_my_permissions) // Gets permissions for current user, as well as other profiles to access

            // Waiver routes
            .service(handlers::get_latest_waiver)
            .service(handlers::accept_waiver_handler)
            .service(handlers::create_waiver_handler)

            // Class routes
            .service(handlers::create_class_handler)
            .service(handlers::get_class_list_handler)
            .service(handlers::get_class_handler)
            .service(handlers::update_class_handler)
            .service(handlers::get_class_students_handler)
            .service(handlers::set_class_student_attendance_handler)
            .service(handlers::get_class_history_handler)

            // Venue routes
            .service(handlers::create_venue_handler)
            .service(handlers::get_venue_list_handler)
            .service(handlers::get_venue_handler)
            .service(handlers::update_venue_handler)

            // Style routes
            .service(handlers::create_style_handler)
            .service(handlers::get_style_list_handler)
            .service(handlers::get_style_handler)
            .service(handlers::update_style_handler)

            // Payment routes
            .service(handlers::create_setup_intent_handler)
            .service(handlers::get_stripe_saved_payment_methods_handler)
            .service(handlers::delete_payment_method_handler)

            // School routes - protected for admin
            .service(handlers::get_school_current_payment_plans_handler)
            .service(handlers::update_school_payment_plan_handler)
            .service(handlers::get_school_users_handler)
            .service(handlers::get_school_settings_handler)
            .service(handlers::update_school_settings_handler)
            .service(handlers::admin_get_user_data)
            .service(handlers::admin_invite_logged_user)
            .service(handlers::get_dashboard_data)
    })
    .bind(format!("0.0.0.0:{}", port))?
    .run();
    
    // Wait for server to finish
    server.await?;
    
    Ok(())
}
