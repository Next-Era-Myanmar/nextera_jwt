# Next Era Actix Web Authentication Macro

This crate provides procedural macro attributes to easily secure Actix Web endpoints using JWTs and API keys. Developed by **Next Era Solutions**.

## ✨ Provided Macros

- `#[authentication]`: Validates **access tokens** using the `Authorization` header.
- `#[refresh_authentication]`: Validates **refresh tokens** using the `Authorization` header.
- `#[x_api_key]`: Validates requests using the `X-API-Key` header.

## 🔐 JWT Authentication Flow

1. Extracts the token from `Authorization: Bearer <token>`.
2. Loads secrets from environment:
   - `ACCESS_TOKEN_SECRET`
   - `REFRESH_TOKEN_SECRET`
   - `JWT_AUDIENCE`
3. Uses `nextera_utils::jwt::validate_jwt()` for validation.
4. Returns 401 or 419 (session expired) based on JWT errors.
5. Injects `HttpRequest` into your handler function.

## 🌐 Localization

Supports localization based on `Content-Language` header:
- `en` (default)
- `zh-CN`
- `th`
- `mm`

## 🧪 Example Usage

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
async fn x_api_key() -> impl Responder {
    HttpResponse::Ok().body("Valid X API Key")
}
```

## ✅ Required Environment Variables

| Variable               | Purpose                          |
|------------------------|----------------------------------|
| `ACCESS_TOKEN_SECRET`  | Secret for validating access JWT |
| `REFRESH_TOKEN_SECRET` | Secret for validating refresh JWT|
| `JWT_AUDIENCE`         | Audience claim for validation    |
| `X_API_KEY`            | API key expected in header       |

## ⚠️ Warnings

- Current version uses `unwrap_or` and `expect()`; improve error handling for production.
- Automatically injects `HttpRequest` as first argument in handler.
- Requires `nextera_utils` crate.

## 📜 License

MIT License © 2025 Next Era Solutions
