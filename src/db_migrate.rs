// use scylla::transport::query_result;
use std::fs;
use std::path::{Path, PathBuf};
use tokio;
use std::sync::Arc;
use scylla::client::session::Session;
// use scylla::transport::errors::QueryError;
// use scylla::{QueryResult, Session, SessionBuilder};
use crate::error::{AppError, Result, Result as AppResult};

pub struct MigrationTool {
    keyspace: String,
    schema_path: PathBuf,
}

impl MigrationTool {
    /// Create a new MigrationTool.
    pub fn new(keyspace: String, schema_path: PathBuf) -> Self {
        println!("Migration tool ks:{}", keyspace);
        Self {
            keyspace,
            schema_path,
        }
    }

    // Ensure `schema_migrations` table exists. If empty, assume version 0.
    async fn ensure_migration_table(&self, session: &Session) -> AppResult<()> {
        let create_table = format!(
            "CREATE TABLE IF NOT EXISTS {}.schema_version (
                version int,
                applied_at timestamp,
                db int primary key
            )",
            self.keyspace
        );
    
        session
            .query_unpaged(create_table, &[])
            .await
            .map_err(|_| AppError::Internal("Unable to create schema_version table".to_string()))?;
    
        Ok(())
    }

    async fn get_current_version(&self, session: &Session) -> Result<i32> {
        let select = format!(
            "SELECT version FROM {}.schema_version LIMIT 1",
            self.keyspace
        );
    
        // Execute the query
        let query_result = session.query_unpaged(select, &[]).await?;
    
        // Convert to Rows (or return an error if the query wasn't a Rows response).
        let rows = query_result.into_rows_result()?; 
    
        // Convert all rows into a typed iterator (in this case, a single i32 column).
        let mut typed_rows = rows.first_row::<(i32,)>();
    
        // Grab the first row if it exists.
        if let Ok(version) = typed_rows {
            Ok(version.0)
        } else {
            // If there are no rows, return 0 by default
            Ok(0)
        }
    }

    /// Insert or update the schema_migrations table to a new version.
    async fn set_version(&self, session: &Session, version: i32) -> AppResult<()> {
        let cql: String = format!(
            "insert into {}.schema_version (version, applied_at, db) values (?, toTimestamp(now()), 0)",
            self.keyspace
        );
        session
            .query_unpaged(cql.clone(), (version,))
            .await
            .map_err(|e| AppError::Internal(format!("Failed to update schema_version to new version cql:{}", cql)))?;
            // .context(format!("Failed to update schema_version to new version cql:{}", cql))?;
        Ok(())
    }

    /// Read a .cql file and execute all statements (split by `;` or any logic you prefer).
    async fn execute_cql_file(&self, session: &Session, file_path: &Path) -> AppResult<()> {
        let contents = fs::read_to_string(file_path)
        .map_err(|e| AppError::Internal(format!("Failed to read file {:?}", file_path)))?;

        // A simplistic split on `;` might break for complex statements; adapt as needed.
        for statement in contents.split(';') {
            let st1 = statement.trim();
            let stmt = st1.replace("{}", &self.keyspace);
            if !stmt.is_empty() {
                // println!("cql update: {} {}", stmt, stmt.len());

                session
                    .query_unpaged(stmt.clone(), &[])
                    .await
                    .map_err(|e| AppError::Internal(format!("Error executing CQL: {}", stmt)))?;

                    // .with_context(|| format!("Error executing CQL: {}", stmt))?;
            }
        }

        Ok(())
    }

    /// Main function: Migrate from the current version up to `target_version`.
    pub async fn migrate_to_version(&self,  session: &Session, target_version: i32) -> AppResult<()> {
        // Ensure the migration table is present
        self.ensure_migration_table(session).await?;

        // Determine current DB version
        let mut current_version = self.get_current_version(session).await?;
        println!("Current DB version is: {}", current_version);

        // Gather all version directories (sorted by integer)
        let mut versions: Vec<i32> = fs::read_dir(&self.schema_path)
        .map_err(|_| AppError::Internal("Unable to read cql schemas directory".to_string()))?
        .filter_map(|entry| {
            if let Ok(e) = entry {
                let path = e.path();
                if path.is_dir() {
                    if let Some(fname) = path.file_name() {
                        if let Ok(ver) = fname.to_string_lossy().parse::<i32>() {
                            return Some(ver);
                        }
                    }
                }
            }
            None
        })
        .collect();

        versions.sort_unstable();

        // Apply each version, from current_version+1 up to target_version
        for v in versions {
            if v > current_version && v <= target_version {
                // We'll apply the update_schema.cql
                let version_path = self.schema_path.join(v.to_string());
                let update_file = version_path.join("update_schema.cql");
                let init_file = version_path.join("init_schema.cql");

                println!("Upgrading from {} to {}", current_version, v);

                // If this is a brand-new DB (version 0), and we are at the first version:
                // we might apply `init_schema` instead of `update_schema`.
                // Or if you prefer always to run update_schema, do that.
                if current_version == 0 {
                    if init_file.exists() {
                        println!("Applying full init_schema for version {}", v);
                        self.execute_cql_file(session, &init_file).await?;
                    } /*else if update_file.exists() {
                        println!("Applying update_schema for version {}", v);
                        self.execute_cql_file(&update_file).await?;
                    } */else {
                        println!(
                            "No init_schema.cql or update_schema.cql for version {} - skipping.",
                            v
                        );
                    }
                } else {
                    // Normal path: apply update_schema
                    if update_file.exists() {
                        println!("Applying update_schema for version {}", v);
                        self.execute_cql_file(session, &update_file).await?;
                    } else /*if init_file.exists() {
                        println!("No update_schema.cql found; fallback to init_schema for {}", v);
                        self.execute_cql_file(&init_file).await?;
                    } else */ {
                        println!("No migration scripts found for version {} - skipping.", v);
                    }
                }

                // Here you could add optional verification steps to compare actual vs. init_schema
                // e.g., self.verify_schema_matches_init(&init_file).await?;

                // If everything OK, set version in DB
                self.set_version(session, v).await?;
                current_version = v;
                println!("Database schema migrated to version {}", current_version);
            }
        }

        if current_version < target_version {
            println!(
                "No more migration scripts found, but target_version={} > current_version={}",
                target_version, current_version
            );
        } else {
            println!("Migration completed. DB is now at version {}", current_version);
        }

        Ok(())
    }
}