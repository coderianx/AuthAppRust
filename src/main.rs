use axum::{Json, Router, extract::State, http::StatusCode, routing::get, routing::post};
use bcrypt::{DEFAULT_COST, hash, verify};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use std::net::SocketAddr;

#[derive(Clone)]
struct AppState {
    db: SqlitePool,
}

#[derive(Deserialize)]
struct RegisterRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct Response {
    message: String,
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[tokio::main]
async fn main() {
    let db = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(
            SqliteConnectOptions::new()
                .filename("auth.db")
                .create_if_missing(true)
                .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal),
        )
        .await
        .expect("SQLite bağlantısı kurulamadı");

    sqlx::query(
        "
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        );
        ",
    )
    .execute(&db)
    .await
    .expect("DB sorgusu başarısız");

    let state = AppState { db };

    let app = Router::new()
        .route("/health", get(health))
        .route("/register", post(register))
        .route("/login", post(login))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Port bağlanamadı");

    println!("Server çalışıyor: http://{addr}");
    axum::serve(listener, app).await.unwrap();
}

async fn health(State(state): State<AppState>) -> &'static str {
    sqlx::query("SELECT 1")
        .execute(&state.db)
        .await
        .expect("DB sorgusu başarısız");
    "ok"
}

async fn register(
    State(state): State<AppState>,
    Json(user): Json<RegisterRequest>,
) -> Result<Json<Response>, (StatusCode, Json<Response>)> {
    if user.password.len() < 8 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(Response {
                message: "Şifre en az 8 karakter olmalı".to_string(),
            }),
        ));
    }

    let password_hash = hash(&user.password, DEFAULT_COST).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Response {
                message: format!("Şifre hash'lenemedi: {e}"),
            }),
        )
    })?;

    let result = sqlx::query("INSERT INTO users (username, password) VALUES (?, ?)")
        .bind(&user.username)
        .bind(&password_hash)
        .execute(&state.db)
        .await;

    match result {
        Ok(_) => Ok(Json(Response {
            message: "Kullanıcı başarıyla kaydedildi".to_string(),
        })),
        Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => Err((
            StatusCode::CONFLICT,
            Json(Response {
                message: "Bu kullanıcı adı zaten alınmış".to_string(),
            }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Response {
                message: e.to_string(),
            }),
        )),
    }
}

async fn login(
    State(state): State<AppState>,
    Json(credentials): Json<LoginRequest>,
) -> Result<Json<Response>, (StatusCode, Json<Response>)> {
    let row: Option<(String,)> = sqlx::query_as("SELECT password FROM users WHERE username = ?")
        .bind(&credentials.username)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Response {
                    message: e.to_string(),
                }),
            )
        })?;

    let valid = match row {
        Some((password_hash,)) => verify(&credentials.password, &password_hash).unwrap_or(false),
        None => false,
    };

    if valid {
        Ok(Json(Response {
            message: "Giriş başarılı".to_string(),
        }))
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(Response {
                message: "Kullanıcı adı veya şifre hatalı".to_string(),
            }),
        ))
    }
}
