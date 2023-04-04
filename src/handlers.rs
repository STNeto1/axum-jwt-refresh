use std::sync::{Arc, Mutex};

use axum::{
    async_trait,
    extract::{FromRequestParts, State, TypedHeader},
    headers::{authorization::Bearer, Authorization},
    http::request::Parts,
    Json, RequestPartsExt,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

use crate::{errors::AuthError, user::User, AppContext};

static KEYS: Lazy<Keys> = Lazy::new(|| {
    let secret = std::env::var("JWT_SECRET").unwrap_or("secret".to_string());
    Keys::new(secret.as_bytes())
});

struct Keys {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl Keys {
    fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    sub: i32,
    exp: usize,
}

#[async_trait]
impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::InvalidToken)?;
        // Decode the user data
        let token_data = decode::<Claims>(bearer.token(), &KEYS.decoding, &Validation::default())
            .map_err(|_| AuthError::InvalidToken)?;

        if token_data.claims.exp < (chrono::Utc::now()).timestamp() as usize {
            return Err(AuthError::TokenExpired);
        }

        Ok(token_data.claims)
    }
}

#[derive(Debug, Serialize)]
pub struct AuthBody {
    access_token: String,
    refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthPayload {
    pub username: String,
    pub password: String,
}

pub async fn login(
    State(ctx): State<Arc<Mutex<AppContext>>>,
    Json(payload): Json<AuthPayload>,
) -> Result<Json<AuthBody>, AuthError> {
    let app_ctx = ctx.try_lock().map_err(|_| AuthError::Internal)?;

    // Find the user in the database
    let user = app_ctx
        .user_store
        .find_by_username(&payload.username)
        .ok_or(AuthError::WrongCredentials)?;

    // Check if the password is correct
    if user.password != payload.password {
        return Err(AuthError::WrongCredentials);
    }

    let auth_body = AuthBody {
        access_token: create_access_token(&user)?,
        refresh_token: create_refresh_token(&user)?,
    };

    return Ok(Json(auth_body));
}

pub async fn register(
    State(ctx): State<Arc<Mutex<AppContext>>>,
    Json(payload): Json<AuthPayload>,
) -> Result<Json<AuthBody>, AuthError> {
    let mut app_ctx = ctx.try_lock().map_err(|_| AuthError::Internal)?;

    // Find the user in the database
    let current_user = app_ctx.user_store.find_by_username(&payload.username);

    if current_user.is_some() {
        return Err(AuthError::UsernameAlreadyExists);
    }

    let user = app_ctx
        .user_store
        .create_new_user(&payload.username, &payload.password);

    let auth_body = AuthBody {
        access_token: create_access_token(&user)?,
        refresh_token: create_refresh_token(&user)?,
    };

    return Ok(Json(auth_body));
}

pub async fn profile(
    Claims { sub, .. }: Claims,
    State(ctx): State<Arc<Mutex<AppContext>>>,
) -> Result<Json<User>, AuthError> {
    let app_ctx = ctx.try_lock().map_err(|_| AuthError::Internal)?;

    // Find the user in the database
    let user = app_ctx
        .user_store
        .find_by_id(sub)
        .ok_or(AuthError::WrongCredentials)?;

    return Ok(Json(User {
        id: user.id,
        username: user.username.clone(),
        password: "".to_string(),
    }));
}

pub async fn refresh(
    Claims { sub, .. }: Claims,
    State(ctx): State<Arc<Mutex<AppContext>>>,
) -> Result<Json<AuthBody>, AuthError> {
    let app_ctx = ctx.try_lock().map_err(|_| AuthError::Internal)?;

    // Find the user in the database
    let user = app_ctx
        .user_store
        .find_by_id(sub)
        .ok_or(AuthError::TokenExpired)?;

    let auth_body = AuthBody {
        access_token: create_access_token(&user)?,
        refresh_token: create_refresh_token(&user)?,
    };

    return Ok(Json(auth_body));
}

fn create_access_token(user: &User) -> Result<String, AuthError> {
    let claims = Claims {
        sub: user.id,
        exp: (chrono::Utc::now() + chrono::Duration::minutes(1)).timestamp() as usize,
    };

    encode(&Header::default(), &claims, &KEYS.encoding).map_err(|_| AuthError::TokenCreation)
}

fn create_refresh_token(user: &User) -> Result<String, AuthError> {
    let claims = Claims {
        sub: user.id,
        exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
    };

    encode(&Header::default(), &claims, &KEYS.encoding).map_err(|_| AuthError::TokenCreation)
}
