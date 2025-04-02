# Actix Web Authentication Macro

This project provides a custom procedural macro attribute (`#[authentication]`) for easily adding JWT (JSON Web Token) authentication to your Actix Web handlers.

### Add macro to your project

```sh
    cargo add nextera_jwt
```

### Prepare your `.env` file

* JWT_AUDIENCE = your_audience_name
* ACCESS_TOKEN_SECRET = your_access_token_secret
* REFRESH_TOKEN_SECRET = your_refresh_token_secret

## Features

* __Automatic `HttpRequest` Injection:__ The macro automatically injects an `actix_web::HttpRequest` instance as the first argument of the decorated function, allowing you to access request information.
* **JWT Authentication:** Performs JWT-based authentication by extracting the `Authorization` header from the request and validating the token against a provided secret key and audience.
* __Environment Variable Configuration:__ Retrieves the JWT audience and secret key from environment variables (`JWT_AUDIENCE` and `ACCESS_TOKEN_SECRET`), promoting secure configuration management.
* **Unauthorized Response:** Returns an `HttpResponse::Unauthorized` (401) response if the authentication fails.
* **Supports Async Functions:** Compatible with asynchronous handlers.

## Usage

1. **Add the Macro to Your Project:**

   * Place the macro code (from the provided example) in a separate file (e.g., `src/lib.rs`) within your project.
   * Add the path to this file in your `Cargo.toml` under `[lib]` -> `path`.

2. **Decorate Your Handlers:**

* Apply the `#[authentication]` attribute to the handlers that require to check access token:
* Apply the `#[refresh_authentication]` attribute to the handlers that require to check refresh token:

```rust
use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use nextera_jwt::authentication;
use nextera_jwt::refresh_authentication;

#[authentication]
async fn my_protected_handler(req: actix_web::HttpRequest, data: web::Data<AppState>) -> impl Responder {
    // ... your handler logic ...
}

#[refresh_authentication]
async fn my_refresh_protected_handler(req: actix_web::HttpRequest, data: web::Data<AppState>) -> impl Responder {
    // ... your handler logic ...
}
```

3. **Set Environment Variables:**

   * Before running your application, set the following environment variables:
      * `JWT_AUDIENCE`: The intended audience for the JWT.
      * `ACCESS_TOKEN_SECRET`: The secret key used to sign the JWT.
      * `REFRESH_TOKEN_SECRET`: The secret key used to sign the JWT of refresh token.

4. **Run Your Application:**

   * Build and run your Actix Web application as usual.

## Example

See the `example` directory for a complete, working example demonstrating the usage of the authentication macro with Actix Web.

## Important Considerations

* **Error Handling:** The provided example uses basic error handling. For production environments, implement more robust error handling (e.g., handle missing headers gracefully, return appropriate error responses).
* **Security:**
   * **Never hardcode secrets directly in your code.** Utilize environment variables or a secrets management solution for secure configuration.
   * **Regularly rotate your secret keys** to enhance security.

* **Dependencies:** This macro may have dependencies on other crates (e.g., for JWT validation). Ensure these dependencies are correctly listed in your `Cargo.toml`.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for any improvements or bug fixes.

This `README.md` provides a comprehensive overview of the project, its features, usage, and important considerations. Remember to adapt it further based on your specific project needs and any additional functionalities you may implement.