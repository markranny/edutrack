// src-tauri/src/bin/migration.rs
use rusqlite::{Connection, Result};
use std::path::PathBuf;

fn main() -> Result<()> {
    println!("🚀 Starting EduTrack database migration...");
    
    // Old database path (in project root)
    let old_db_path = "../../my_database.db";
    
    // New database path
    let mut new_path = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
    new_path.push("edutrack");
    std::fs::create_dir_all(&new_path).ok();
    new_path.push("database.db");
    
    println!("📁 Looking for old database at: {}", old_db_path);
    println!("📂 New database location: {:?}", new_path);
    
    // Check if old database exists
    if !std::path::Path::new(old_db_path).exists() {
        println!("ℹ️  No old database found at {}", old_db_path);
        println!("🎯 Creating fresh database structure...");
        
        // Create new database with proper structure
        let new_db = Connection::open(&new_path)?;
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
        
        println!("✅ Fresh database created successfully!");
        return Ok(());
    }
    
    // Connect to old database
    let old_db = Connection::open(old_db_path)?;
    
    // Create new database
    let new_db = Connection::open(&new_path)?;
    
    // Create new table structure
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
    
    // Check if old table exists and has data
    let mut stmt = old_db.prepare("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='users'")?;
    let table_exists: i64 = stmt.query_row([], |row| row.get(0))?;
    
    if table_exists > 0 {
        println!("📋 Found existing users table, migrating data...");
        
        // Read all users from old database
        let mut stmt = old_db.prepare("SELECT id, firstname, lastname, email, password, role FROM users")?;
        let user_iter = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })?;
        
        let mut migrated_count = 0;
        
        for user in user_iter {
            let (id, firstname, lastname, email, password, role) = user?;
            
            // Insert into new database using rusqlite::params! macro
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
        
        println!("🎉 Migration completed! Migrated {} users.", migrated_count);
        println!("📝 Old database can be safely deleted: {}", old_db_path);
    } else {
        println!("ℹ️  No users table found in old database. Starting fresh.");
    }
    
    println!("✨ Database migration finished successfully!");
    Ok(())
}