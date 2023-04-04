use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use axum::{routing, Router};

mod errors;
mod handlers;
mod user;

pub struct AppContext {
    pub user_store: user::UserStore,
}

#[tokio::main]
async fn main() {
    let app_context = Arc::new(Mutex::new(AppContext {
        user_store: user::UserStore::new(),
    }));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    let app = Router::new()
        .route("/login", routing::post(handlers::login))
        .route("/register", routing::post(handlers::register))
        .route("/profile", routing::get(handlers::profile))
        .route("/refresh", routing::post(handlers::refresh))
        .with_state(app_context);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
