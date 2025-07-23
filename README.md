# 🛡️ Next Era Actix Web Authentication Macros

> Procedural macro attributes for seamless JWT and API key-based authentication in [Actix Web](https://actix.rs/), developed by **Next Era Solutions**.

---

## ✨ Overview

This crate provides three procedural macro attributes:

- `#[authentication]` — Validates an **Access Token**.
- `#[refresh_authentication]` — Validates a **Refresh Token**.
- `#[x_api_key]` — Validates a request using an **X-API-Key**.

All three macros inject an `actix_web::HttpRequest` into your handler, extract headers, validate secrets, and return an `Unauthorized` response if validation fails.

---

## 🚀 Usage

### 1. Add dependencies

Add the following to your `Cargo.toml`:

```toml
[dependencies]
actix-web = "4"
nextera_utils = { path = "../nextera_utils" } # adjust as needed
```

Add the macro crate as a dependency:

```toml
[lib]
proc-macro = true
```

---

### 2. Define Handlers

```rust
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use nextera_jwt::{authentication, refresh_authentication, x_api_key};

#[get("/auth")]
#[authentication]
pub async fn auth() -> impl Responder {
    HttpResponse::Ok().body("Valid Access Token")
}

#[get("/refresh")]
#[refresh_authentication]
async fn refresh() -> impl Responder {
    HttpResponse::Ok().body("Valid Refresh Token")
}

#[get("/apikey")]
#[x_api_key]
async fn apikey() -> impl Responder {
    HttpResponse::Ok().body("Valid API Key")
}

#[get("/")]
async fn public() -> impl Responder {
    HttpResponse::Ok().body("Public Endpoint")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("ACCESS_TOKEN_SECRET", "my_access_secret");
    std::env::set_var("REFRESH_TOKEN_SECRET", "my_refresh_secret");
    std::env::set_var("X_API_KEY", "my_api_key");

    HttpServer::new(|| {
        App::new()
            .service(public)
            .service(auth)
            .service(refresh)
            .service(apikey)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

---

## 🧠 How It Works

Each macro:

1. Extracts the corresponding header from `HttpRequest`.
2. Parses the header for the token or key.
3. Validates it using:
    - `nextera_utils::jwt::validate_jwt` for JWT tokens.
    - Direct comparison for `X_API_KEY`.
4. If validation fails, responds with:

```json
{ "message": "Invalid credentials" }
```

Supports language-specific messages in:
- English (default)
- Chinese (zh-CN)
- Thai (th)
- Burmese (mm)

---

## ⚠️ Important Notes

- **Async Support:** All macros work on async handlers.
- **HttpRequest Injection:** `HttpRequest` is auto-injected as the first argument.
- **Error Handling:** Currently uses `.unwrap_or("")` and `.expect`. Improve error handling for production use.
- **Environment Variables:**
    - `ACCESS_TOKEN_SECRET`
    - `REFRESH_TOKEN_SECRET`
    - `X_API_KEY`
- **Dependency:** Requires `nextera_utils` crate for JWT handling and shared types.

---

## 📂 Project Structure

```
nextera_jwt/
├── src/
│   ├── lib.rs               # Procedural macro implementations
├── Cargo.toml
├── README.md
```

---

## 📜 License

This project is licensed under the [MIT License](LICENSE). Free for personal and commercial use.

---

## 👨‍💻 Developed By

**Next Era Solutions**

Crafting secure and modular backend solutions for modern Rust web apps.