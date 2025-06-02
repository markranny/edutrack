// src-tauri/src/bin/migration.rs
use rusqlite::{Connection, Result};
use std::path::PathBuf;

fn main() -> Result<()> {
    println!("🚀 Starting EduTrack database migration...");
    
    // Old database paths to check
    let old_db_paths = vec![
        "my_database.db",
        "../my_database.db", 
        "../../my_database.db",
        "src-tauri/my_database.db"
    ];
    
    // New database path
    let mut new_path = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
    new_path.push("edutrack");
    std::fs::create_dir_all(&new_path).ok();
    new_path.push("database.db");
    
    println!("📂 New database location: {:?}", new_path);
    
    // Create new database connection
    let new_db = Connection::open(&new_path)?;
    
    // Drop existing table to ensure clean schema
    println!("🗑️  Dropping existing tables...");
    new_db.execute("DROP TABLE IF EXISTS users", [])?;
    
    // Create the users table with correct schema
    println!("🏗️  Creating new table schema...");
    new_db.execute(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            firstname TEXT NOT NULL,
            lastname TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;
    
    // Try to find and migrate from old database
    let mut migrated = false;
    for old_path in &old_db_paths {
        if std::path::Path::new(old_path).exists() {
            println!("📋 Found old database at: {}", old_path);
            
            match migrate_from_old_db(old_path, &new_db) {
                Ok(count) => {
                    println!("✅ Successfully migrated {} users from {}", count, old_path);
                    migrated = true;
                    break;
                }
                Err(e) => {
                    println!("⚠️  Failed to migrate from {}: {}", old_path, e);
                    continue;
                }
            }
        }
    }
    
    if !migrated {
        println!("ℹ️  No old database found or migration failed. Starting with fresh database.");
        println!("🎯 You can now create new accounts through the signup page.");
    }
    
    // Create a test admin account if no users exist
    let user_count: i64 = new_db.query_row(
        "SELECT COUNT(*) FROM users", 
        [], 
        |row| row.get(0)
    )?;
    
    if user_count == 0 {
        println!("👤 Creating default admin account...");
        // Hash a default password
        let default_password = "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8.iwckiUlAkDhG6oPt6"; // "admin123"
        
        new_db.execute(
            "INSERT INTO users (firstname, lastname, email, password, role) VALUES (?1, ?2, ?3, ?4, ?5)",
            &["Admin", "User", "admin@edutrack.com", default_password, "teacher"],
        )?;
        
        println!("✅ Default admin account created:");
        println!("   Email: admin@edutrack.com");
        println!("   Password: admin123");
        println!("   Role: teacher");
    }
    
    println!("✨ Database migration completed successfully!");
    Ok(())
}

fn migrate_from_old_db(old_path: &str, new_db: &Connection) -> Result<i32> {
    let old_db = Connection::open(old_path)?;
    
    // Check if old table exists
    let table_exists: i64 = old_db.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='users'",
        [],
        |row| row.get(0),
    )?;
    
    if table_exists == 0 {
        return Ok(0);
    }
    
    // Get old table schema
    let mut stmt = old_db.prepare("PRAGMA table_info(users)")?;
    let column_info: Vec<String> = stmt.query_map([], |row| {
        Ok(row.get::<_, String>(1)?) // column name
    })?.collect::<Result<Vec<_>, _>>()?;
    
    println!("📊 Old database columns: {:?}", column_info);
    
    let has_firstname = column_info.contains(&"firstname".to_string());
    let has_lastname = column_info.contains(&"lastname".to_string());
    
    let mut migrated_count = 0;
    
    if has_firstname && has_lastname {
        // New schema - direct migration
        let mut stmt = old_db.prepare("SELECT id, firstname, lastname, email, password, role FROM users")?;
        let user_iter = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,      // id
                row.get::<_, String>(1)?,   // firstname
                row.get::<_, String>(2)?,   // lastname
                row.get::<_, String>(3)?,   // email
                row.get::<_, String>(4)?,   // password
                row.get::<_, String>(5)?,   // role
            ))
        })?;
        
        for user in user_iter {
            let (id, firstname, lastname, email, password, role) = user?;
            
            match new_db.execute(
                "INSERT OR REPLACE INTO users (id, firstname, lastname, email, password, role) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![id, &firstname, &lastname, &email, &password, &role],
            ) {
                Ok(_) => {
                    migrated_count += 1;
                    println!("✅ Migrated user: {} {} ({})", firstname, lastname, email);
                }
                Err(e) => {
                    println!("❌ Error migrating user {}: {}", email, e);
                }
            }
        }
    } else {
        // Old schema - need to create firstname/lastname from email or use defaults
        let mut stmt = old_db.prepare("SELECT id, email, password, role FROM users")?;
        let user_iter = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,      // id
                row.get::<_, String>(1)?,   // email
                row.get::<_, String>(2)?,   // password
                row.get::<_, String>(3)?,   // role
            ))
        })?;
        
        for user in user_iter {
            let (id, email, password, role) = user?;
            
            // Extract name from email or use defaults
            let email_parts: Vec<&str> = email.split('@').collect();
            let name_part = email_parts[0];
            let (firstname, lastname) = if name_part.contains('.') {
                let parts: Vec<&str> = name_part.split('.').collect();
                (parts[0].to_string(), parts.get(1).unwrap_or(&"User").to_string())
            } else {
                (name_part.to_string(), "User".to_string())
            };
            
            match new_db.execute(
                "INSERT OR REPLACE INTO users (id, firstname, lastname, email, password, role) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![id, &firstname, &lastname, &email, &password, &role],
            ) {
                Ok(_) => {
                    migrated_count += 1;
                    println!("✅ Migrated user: {} {} ({})", firstname, lastname, email);
                }
                Err(e) => {
                    println!("❌ Error migrating user {}: {}", email, e);
                }
            }
        }
    }
    
    Ok(migrated_count)
}