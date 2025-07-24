# Next Era Actix Web Authentication Macro

**Next Era Solutions** provides a procedural macro-based authentication system for Actix Web using JWT and API Key mechanisms.

## ✨ Features

- ✅ Simple attribute macros for securing routes:
    - `#[authentication]` — Validates access tokens.
    - `#[refresh_authentication]` — Validates refresh tokens.
    - `#[x_api_key]` — Validates API key headers.
- 🌍 Multilingual error messages (`en`, `zh-CN`, `th`, `mm`).
- 🔐 Environment variable-based secret management.
- 🔧 Easy to integrate with `actix_web`.

## 🚀 Usage Example

```rust
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use nextera_jwt::{authentication, refresh_authentication, x_api_key};

#[authentication]
async fn auth() -> impl Responder {
    HttpResponse::Ok().body("Valid Token")
}

#[refresh_authentication]
async fn refresh_auth() -> impl Responder {
    HttpResponse::Ok().body("Valid Refresh Token")
}

#[x_api_key]
async fn x_api_key_route() -> impl Responder {
    HttpResponse::Ok().body("Valid X API Key")
}
```

## ✅ Environment Variables

| Variable               | Description                         |
|------------------------|-------------------------------------|
| `ACCESS_TOKEN_SECRET`  | Secret key for validating JWT access tokens |
| `REFRESH_TOKEN_SECRET` | Secret key for validating JWT refresh tokens |
| `JWT_AUDIENCE`         | Expected JWT audience claim         |
| `X_API_KEY`            | API key used in `X-API-Key` header  |

Set these before running your application.

## 🧪 Tests

Unit tests demonstrate how the macros work:

```rust
#[actix_web::test]
async fn test_access_and_refresh_token() {
    // Setup, generate tokens, and test both access and refresh endpoints
}
```

```rust
#[actix_web::test]
async fn test_api_key() {
    // Setup and validate X-API-Key logic
}
```

## ⚠️ Considerations

- The current implementation uses `unwrap_or("")` and `expect()`. Add error handling before using in production.
- Injects `HttpRequest` automatically into handlers — ensure compatibility with your handler signatures.
- Requires `nextera_utils` crate for token validation.

## 📦 Cargo.toml Example

```toml
[dependencies]
actix-web = "4"
nextera_utils = { path = "../nextera_utils" } # Or use crate version
nextera_jwt = { path = "../nextera_jwt" }
```

## 📜 License

MIT License © 2025 Next Era Solutions
