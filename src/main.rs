use axum::{Json, Router, extract::State, routing::get, routing::post};
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
            id BIGINT PRIMARY KEY,
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
) -> Json<Response> {
    let result = sqlx::query("INSERT INTO users (username, password) VALUES (?, ?)")
        .bind(&user.username)
        .bind(&user.password)
        .execute(&state.db)
        .await;

    match result {
        Ok(_) => Json(Response {
            message: "Kullanıcı başarıyla kaydedildi".to_string(),
        }),
        Err(e) => Json(Response {
            message: e.to_string(),
        }),
    }
}

async fn login(
    State(state): State<AppState>,
    Json(credentials): Json<LoginRequest>,
) -> Json<Response> {
    let results = sqlx::query("SELECT * FROM users WHERE username = ? AND password = ?")
        .bind(&credentials.username)
        .bind(&credentials.password)
        .fetch_all(&state.db)
        .await;

    match results {
        Ok(_) => Json(Response {
            message: "Giriş başarılı".to_string(),
        }),
        Err(e) => Json(Response {
            message: e.to_string(),
        }),
    }
}
