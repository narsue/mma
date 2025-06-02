use criterion::{black_box, criterion_group, criterion_main, Criterion};
use actix_web::{test, web, App, http::StatusCode};
use mma::templates::load_templates;
use mma::server::handlers;
use mma::api::LoginRequest; // You'll need to make this public in your models
use mma::db::ScyllaConnector;
use mma::state::StoreStateManager;
use tokio::runtime::Runtime;
use std::sync::Arc;

fn home_page_integration_benchmark(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    let template_cache = rt.block_on(async {
        load_templates().expect("Failed to load templates for benchmark")
    });
    let template_data = web::Data::new(template_cache);
    
    c.bench_function("home_page_integration", |b| {
        b.iter(|| {
            rt.block_on(async {
                let app = test::init_service(
                    App::new()
                        .app_data(template_data.clone())
                        .service(handlers::home_page)
                ).await;
                
                let req = test::TestRequest::get().uri("/").to_request();
                let resp = test::call_service(&app, req).await;
                
                // Comprehensive response validation
                assert_eq!(resp.status(), StatusCode::OK);
                
                // Verify content type
                if let Some(content_type) = resp.headers().get("content-type") {
                    assert!(content_type.to_str().unwrap().starts_with("text/html"));
                }
                
                // Read and validate body content
                let body = test::read_body(resp).await;
                let body_str = std::str::from_utf8(&body).expect("Response body should be valid UTF-8");
                
                // Basic sanity checks on HTML content
                assert!(body_str.contains("<html") || body_str.contains("<!DOCTYPE"));
                assert!(!body_str.is_empty());
                
                black_box(body);
            })
        });
    });
}

fn login_integration_benchmark(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    
    // Set up database and state manager
    let (template_cache, state_manager) = rt.block_on(async {
        let template_cache = load_templates().expect("Failed to load templates for benchmark");
        
        // Initialize database connection
        let db = Arc::new(
            ScyllaConnector::new(&["127.0.0.1:9042"])
                .await
                .expect("Failed to connect to database for benchmark")
        );
        let state_manager = Arc::new(StoreStateManager::new(db));
        
        (template_cache, state_manager)
    });
    
    let template_data = web::Data::new(template_cache);
    let state_data = web::Data::new(state_manager);
    
    c.bench_function("login_integration", |b| {
        b.iter(|| {
            rt.block_on(async {
                let app = test::init_service(
                    App::new()
                        .app_data(template_data.clone())
                        .app_data(state_data.clone())
                        .service(handlers::user_login)
                ).await;
                
                // Create login request payload
                let login_payload = LoginRequest {
                    email: "narsue@hotmail.com".to_string(),
                    password: "test".to_string(),
                };
                
                let req = test::TestRequest::post()
                    .uri("/api/user/login")
                    .set_json(&login_payload)
                    .to_request();
                
                let resp = test::call_service(&app, req).await;
                
                // Verify response (might be OK for valid credentials or Unauthorized for invalid)
                // We'll check that we get a proper response, not a server error
                assert!(
                    resp.status() == StatusCode::OK || resp.status() == StatusCode::UNAUTHORIZED,
                    "Expected OK or UNAUTHORIZED, got: {}", resp.status()
                );
                
                // Verify content type is JSON
                if let Some(content_type) = resp.headers().get("content-type") {
                    assert!(content_type.to_str().unwrap().contains("application/json"));
                }
                
                // Read and validate body content
                let body = test::read_body(resp).await;
                let body_str = std::str::from_utf8(&body).expect("Response body should be valid UTF-8");
                println!("{}", body_str);
                // Should be valid JSON
                assert!(!body_str.is_empty());
                let _: serde_json::Value = serde_json::from_str(body_str)
                    .expect("Response should be valid JSON");
                
                black_box(body);
            })
        });
    });
}

criterion_group!(benches, home_page_integration_benchmark, login_integration_benchmark);
criterion_main!(benches);