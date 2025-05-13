use actix_web::HttpResponse; // <-- Add this line
use dashmap::DashMap;
use notify::{RecursiveMode, Watcher, event::{ModifyKind, EventKind}};
use notify_debouncer_full::{new_debouncer, DebounceEventResult};
use std::{
    fs,
    io,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
// Type alias for the cache
pub type TemplateCache = Arc<DashMap<String, String>>;

const TEMPLATE_DIR: &str = "templates";
const TEMPLATE_FILES: &[&str] = &[
    "portal.html",
    "home.html",
    "login.html",
    "gym_signup.html",
    "contact.html",
    "contact_confirmation.html",
    "style.css"
];

/// Loads all templates from the TEMPLATE_DIR into the cache.
/// Panics if a template file cannot be read on initial load.
pub fn load_templates() -> io::Result<TemplateCache> {
    let cache: TemplateCache = Arc::new(DashMap::new());
    let base_path = PathBuf::from(TEMPLATE_DIR);

    for filename in TEMPLATE_FILES {
        let path = base_path.join(filename);
        match fs::read_to_string(&path) {
            Ok(content) => {
                cache.insert(filename.to_string(), content);
                tracing::info!("Loaded template: {}", path.display());
            }
            Err(e) => {
                tracing::error!("Failed to load template {}: {}", path.display(), e);
                // Panic on initial load failure, as templates are likely essential
                return Err(io::Error::new(
                    e.kind(),
                    format!("Failed to load essential template: {}", path.display()),
                ));
            }
        }
    }
    Ok(cache)
}

/// Watches the template directory for changes and updates the cache.
/// Runs in a separate Tokio task.
pub async fn watch_templates(cache: TemplateCache) -> notify::Result<()> {
    let template_path = std::env::current_dir()?.join(TEMPLATE_DIR);
    // --- Clone template_path for the closure ---
    let template_path_for_closure = template_path.clone();

    // --- Event Handler ---
    // This closure is called when a debounced event occurs
    let event_handler = move |res: DebounceEventResult| { // Closure still uses move
        match res {

            Ok(events) => {
                for event in events {
                     if matches!(event.kind, EventKind::Modify(ModifyKind::Data(_)) | EventKind::Create(_)) {
                        for path in &event.paths {
                            // --- Use the cloned path inside the closure ---
                            if path.starts_with(&template_path_for_closure) && path.is_file() {
                                if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                                    if TEMPLATE_FILES.contains(&filename) {
                                        match fs::read_to_string(path) {
                                            Ok(new_content) => {
                                                cache.insert(filename.to_string(), new_content);
                                                tracing::info!("Reloaded template: {}", path.display());
                                            }
                                            Err(e) => {
                                                tracing::error!(
                                                    "Failed to reload template {}: {}",
                                                    path.display(),
                                                    e
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Err(errors) => {
                for error in errors {
                     tracing::error!("File watching error: {:?}", error);
                }
            }
        }
    };
    // --- End Event Handler ---


    let mut debouncer = new_debouncer(
        Duration::from_secs(1),
        None,
        event_handler
    )?;


    // --- Use the original template_path for the watch call ---
    debouncer
        .watcher()
        .watch(&template_path, RecursiveMode::Recursive)?; // This now borrows the original, valid path

    // --- Use the original template_path for the cache add_root call ---
     debouncer
        .cache()
        .add_root(&template_path, RecursiveMode::Recursive); // Also uses the original


    tracing::info!("Template watcher started for directory: {}", template_path.display());

    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
    }

    // Ok(()) // This part is unreachable due to the loop, but good practice if the loop could exit
}

/// Helper to get content from cache, returning 404 if not found
pub fn get_template_content(
    cache: &TemplateCache,
    filename: &str,
) -> Result<String, HttpResponse> {
    match cache.get(filename) {
        Some(content) => Ok(content.value().clone()), // Clone the content
        None => {
            tracing::error!("Template not found in cache: {}", filename);
            Err(HttpResponse::NotFound().body(format!("Template {} not found", filename)))
        }
    }
}
