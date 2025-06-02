// src-tauri/src/lib.rs
use rusqlite::{Connection, Result};
use serde::{Deserialize, Serialize};
use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::sync::{Mutex, LazyLock};
use rand::Rng;
use std::path::PathBuf;

// Data structures
#[derive(Debug, Serialize, Deserialize, Clone)]
struct User {
    id: i64,
    firstname: String,
    lastname: String,
    email: String,
    role: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    role: String,
    exp: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
    role: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SignupRequest {
    firstname: String,
    lastname: String,
    email: String,
    password: String,
    role: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ForgotPasswordRequest {
    email: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ResetPasswordRequest {
    email: String,
    reset_token: String,
    new_password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthResponse {
    success: bool,
    message: String,
    user: Option<User>,
    token: Option<String>,
}

// Global state for reset tokens and current user using LazyLock
static RESET_TOKENS: LazyLock<Mutex<HashMap<String, String>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
static CURRENT_USER: LazyLock<Mutex<Option<User>>> = LazyLock::new(|| Mutex::new(None));

const JWT_SECRET: &str = "your-secret-key-here-make-it-strong-in-production";

// Database initialization with proper path
fn get_database_path() -> PathBuf {
    let mut path = dirs::data_dir().unwrap_or_else(|| PathBuf::from("."));
    path.push("edutrack");
    std::fs::create_dir_all(&path).ok();
    path.push("database.db");
    path
}

fn init_database() -> Result<Connection> {
    let db_path = get_database_path();
    println!("Database path: {:?}", db_path);
    
    let conn = Connection::open(&db_path)?;
    
    // Create the users table with the correct schema
    conn.execute(
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
    
    Ok(conn)
}

// JWT token utilities
fn create_jwt_token(email: &str, role: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let expiration = Utc::now()
        .checked_add_signed(Duration::hours(24))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        sub: email.to_owned(),
        role: role.to_owned(),
        exp: expiration as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_ref()),
    )
}

// Validate JWT token
fn validate_jwt_token(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(JWT_SECRET.as_ref()),
        &Validation::default(),
    ).map(|data| data.claims)
}

// Generate random reset token
fn generate_reset_token() -> String {
    let mut rng = rand::thread_rng();
    (0..6).map(|_| rng.gen_range(0..10).to_string()).collect()
}

// Tauri commands
#[tauri::command]
async fn tauri_signup(payload: SignupRequest) -> Result<AuthResponse, String> {
    println!("Signup attempt for: {} as {}", payload.email, payload.role);
    
    let conn = init_database().map_err(|e| format!("Database error: {}", e))?;
    
    // Validate input
    if payload.firstname.trim().is_empty() || payload.lastname.trim().is_empty() {
        return Ok(AuthResponse {
            success: false,
            message: "First name and last name are required".to_string(),
            user: None,
            token: None,
        });
    }
    
    if payload.password.len() < 6 {
        return Ok(AuthResponse {
            success: false,
            message: "Password must be at least 6 characters long".to_string(),
            user: None,
            token: None,
        });
    }
    
    // Check if user already exists
    let email_lower = payload.email.trim().to_lowercase();
    let mut stmt = conn.prepare("SELECT id FROM users WHERE email = ?1")
        .map_err(|e| format!("Database error: {}", e))?;
    
    let user_exists = stmt.exists(&[&email_lower])
        .map_err(|e| format!("Database error: {}", e))?;
    
    if user_exists {
        return Ok(AuthResponse {
            success: false,
            message: "User with this email already exists".to_string(),
            user: None,
            token: None,
        });
    }
    
    // Hash the password
    let hashed_password = hash(&payload.password, DEFAULT_COST)
        .map_err(|e| format!("Password hashing error: {}", e))?;
    
    // Prepare values for insertion
    let firstname = payload.firstname.trim();
    let lastname = payload.lastname.trim();
    let role = &payload.role;
    
    // Insert new user
    conn.execute(
        "INSERT INTO users (firstname, lastname, email, password, role) VALUES (?1, ?2, ?3, ?4, ?5)",
        &[firstname, lastname, &email_lower, &hashed_password, role],
    ).map_err(|e| format!("Database error: {}", e))?;
    
    println!("User registered successfully: {}", email_lower);
    
    Ok(AuthResponse {
        success: true,
        message: "User registered successfully".to_string(),
        user: None,
        token: None,
    })
}

#[tauri::command]
async fn tauri_login(payload: LoginRequest) -> Result<AuthResponse, String> {
    println!("Login attempt for: {} as {}", payload.email, payload.role);
    
    let conn = init_database().map_err(|e| format!("Database error: {}", e))?;
    
    let email = payload.email.trim().to_lowercase();
    
    let mut stmt = conn.prepare("SELECT id, firstname, lastname, email, password, role FROM users WHERE email = ?1 AND role = ?2")
        .map_err(|e| format!("Database error: {}", e))?;
    
    let user_result = stmt.query_row(&[&email, &payload.role], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
        ))
    });
    
    match user_result {
        Ok((id, firstname, lastname, email, hashed_password, role)) => {
            // Verify password
            let password_valid = verify(&payload.password, &hashed_password)
                .map_err(|e| format!("Password verification error: {}", e))?;
            
            if password_valid {
                let user = User {
                    id,
                    firstname: firstname.clone(),
                    lastname: lastname.clone(),
                    email: email.clone(),
                    role: role.clone(),
                };
                
                // Store current user
                {
                    let mut current_user = CURRENT_USER.lock().unwrap();
                    *current_user = Some(user.clone());
                }
                
                let token = create_jwt_token(&email, &role)
                    .map_err(|e| format!("Token creation error: {}", e))?;
                
                println!("Login successful for: {}", email);
                
                Ok(AuthResponse {
                    success: true,
                    message: "Login successful".to_string(),
                    user: Some(user),
                    token: Some(token),
                })
            } else {
                println!("Invalid password for: {}", payload.email);
                Ok(AuthResponse {
                    success: false,
                    message: "Invalid credentials".to_string(),
                    user: None,
                    token: None,
                })
            }
        }
        Err(_) => {
            println!("User not found: {} with role {}", payload.email, payload.role);
            Ok(AuthResponse {
                success: false,
                message: "Invalid credentials".to_string(),
                user: None,
                token: None,
            })
        }
    }
}

#[tauri::command]
async fn get_current_user() -> Result<Option<User>, String> {
    let current_user = CURRENT_USER.lock().unwrap();
    Ok(current_user.clone())
}

#[tauri::command]
async fn change_password(payload: ChangePasswordRequest) -> Result<AuthResponse, String> {
    let current_user_guard = CURRENT_USER.lock().unwrap();
    let current_user = match current_user_guard.as_ref() {
        Some(user) => user.clone(),
        None => {
            return Ok(AuthResponse {
                success: false,
                message: "No user logged in".to_string(),
                user: None,
                token: None,
            });
        }
    };
    drop(current_user_guard);
    
    if payload.new_password.len() < 6 {
        return Ok(AuthResponse {
            success: false,
            message: "New password must be at least 6 characters long".to_string(),
            user: None,
            token: None,
        });
    }
    
    let conn = init_database().map_err(|e| format!("Database error: {}", e))?;
    
    // Get current hashed password
    let mut stmt = conn.prepare("SELECT password FROM users WHERE email = ?1")
        .map_err(|e| format!("Database error: {}", e))?;
    
    let current_hashed_password: String = stmt.query_row(&[&current_user.email], |row| {
        Ok(row.get(0)?)
    }).map_err(|e| format!("Database error: {}", e))?;
    
    // Verify current password
    let password_valid = verify(&payload.current_password, &current_hashed_password)
        .map_err(|e| format!("Password verification error: {}", e))?;
    
    if !password_valid {
        return Ok(AuthResponse {
            success: false,
            message: "Current password is incorrect".to_string(),
            user: None,
            token: None,
        });
    }
    
    // Hash new password
    let new_hashed_password = hash(&payload.new_password, DEFAULT_COST)
        .map_err(|e| format!("Password hashing error: {}", e))?;
    
    // Update password
    conn.execute(
        "UPDATE users SET password = ?1 WHERE email = ?2",
        &[&new_hashed_password, &current_user.email],
    ).map_err(|e| format!("Database error: {}", e))?;
    
    println!("Password changed successfully for: {}", current_user.email);
    
    Ok(AuthResponse {
        success: true,
        message: "Password changed successfully".to_string(),
        user: None,
        token: None,
    })
}

#[tauri::command]
async fn forgot_password(payload: ForgotPasswordRequest) -> Result<AuthResponse, String> {
    let conn = init_database().map_err(|e| format!("Database error: {}", e))?;
    
    let email = payload.email.trim().to_lowercase();
    
    // Check if user exists
    let mut stmt = conn.prepare("SELECT id FROM users WHERE email = ?1")
        .map_err(|e| format!("Database error: {}", e))?;
    
    let user_exists = stmt.exists(&[&email])
        .map_err(|e| format!("Database error: {}", e))?;
    
    if !user_exists {
        return Ok(AuthResponse {
            success: false,
            message: "No user found with this email".to_string(),
            user: None,
            token: None,
        });
    }
    
    // Generate reset token
    let reset_token = generate_reset_token();
    
    // Store reset token
    {
        let mut tokens = RESET_TOKENS.lock().unwrap();
        tokens.insert(email.clone(), reset_token.clone());
    }
    
    println!("Reset token generated for: {} - Token: {}", email, reset_token);
    
    Ok(AuthResponse {
        success: true,
        message: format!("Reset token generated: {}", reset_token),
        user: None,
        token: Some(reset_token),
    })
}

#[tauri::command]
async fn reset_password(payload: ResetPasswordRequest) -> Result<AuthResponse, String> {
    let email = payload.email.trim().to_lowercase();
    
    if payload.new_password.len() < 6 {
        return Ok(AuthResponse {
            success: false,
            message: "New password must be at least 6 characters long".to_string(),
            user: None,
            token: None,
        });
    }
    
    // Verify reset token
    {
        let tokens = RESET_TOKENS.lock().unwrap();
        match tokens.get(&email) {
            Some(stored_token) if *stored_token == payload.reset_token => {},
            _ => {
                return Ok(AuthResponse {
                    success: false,
                    message: "Invalid reset token".to_string(),
                    user: None,
                    token: None,
                });
            }
        }
    }
    
    let conn = init_database().map_err(|e| format!("Database error: {}", e))?;
    
    // Hash new password
    let new_hashed_password = hash(&payload.new_password, DEFAULT_COST)
        .map_err(|e| format!("Password hashing error: {}", e))?;
    
    // Update password
    conn.execute(
        "UPDATE users SET password = ?1 WHERE email = ?2",
        &[&new_hashed_password, &email],
    ).map_err(|e| format!("Database error: {}", e))?;
    
    // Remove reset token
    {
        let mut tokens = RESET_TOKENS.lock().unwrap();
        tokens.remove(&email);
    }
    
    println!("Password reset successfully for: {}", email);
    
    Ok(AuthResponse {
        success: true,
        message: "Password reset successfully".to_string(),
        user: None,
        token: None,
    })
}

#[tauri::command]
async fn logout() -> Result<AuthResponse, String> {
    let mut current_user = CURRENT_USER.lock().unwrap();
    *current_user = None;
    
    println!("User logged out successfully");
    
    Ok(AuthResponse {
        success: true,
        message: "Logged out successfully".to_string(),
        user: None,
        token: None,
    })
}

#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            greet,
            tauri_signup,
            tauri_login,
            get_current_user,
            change_password,
            forgot_password,
            reset_password,
            logout
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}