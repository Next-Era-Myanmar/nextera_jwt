//! # Next Era Actix Web Authentication Macro
//!
//! Next Era Solutions JWT base Procedural Macro Attribute for Actix Web.

extern crate proc_macro;
use proc_macro::TokenStream;

use quote::quote;
use syn::{parse_macro_input, ItemFn};

//// A procedural macro attribute for adding authentication to Actix Web handlers.
///
/// This macro automatically injects an `actix_web::HttpRequest` parameter into the decorated function
/// and performs JWT (JSON Web Token) based authentication. It expects a Bearer token in the
/// `Authorization` header of the incoming request.
///
/// # How it Works
///
/// 1.  **Header Extraction:** It extracts the `Authorization` header from the incoming request.
/// 2.  **Bearer Token Parsing:** It expects the header value to be in the format "Bearer <token>" and extracts the token.
/// 3.  **Environment Variables:** It retrieves the JWT secret key from environment variables named  `ACCESS_TOKEN_SECRET` and `REFRESH_TOKEN_SECRET`, respectively. Make sure these are set before running your application.
/// 4.  **Token Validation:** It uses the `nextera_utils::jwt::validate_jwt` function to validate the token against the provided secret.
/// 5.  **Authorization:** If the token is valid, the original handler function is executed. Otherwise, an `HttpResponse::Unauthorized` (401) response is returned.
///
/// # Usage
///
/// ```rust
/// use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
/// use nextera_jwt::authentication;
/// use nextera_jwt::refresh_authentication;
/// use nextera_jwt::x_api_key;
///
/// #[get("/auth")]
/// #[authentication]
/// pub async fn auth() -> impl Responder {
///     HttpResponse::Ok().body(format!("Valid Token"))
/// }
///
/// #[get("/refresh")]
/// #[refresh_authentication]
/// async fn refresh_auth() -> impl Responder {
///     HttpResponse::Ok().body(format!("Valid Refresh Token"))
/// }
///
/// #[get("/apikey")]
/// #[x_api_key]
/// async fn x_api_key() -> impl Responder {
///     HttpResponse::Ok().body("Valid X API Key")
/// }
///
/// #[get("/")]
/// async fn public_handler() -> impl Responder {
///     HttpResponse::Ok().body("Public Endpoint!")
/// }
///
/// #[actix_web::main]
/// async fn main() -> std::io::Result<()> {
///     std::env::set_var("ACCESS_TOKEN_SECRET", "my_secret_key");
///     std::env::set_var("REFRESH_TOKEN_SECRET", "my_secret_key");
///     std::env::set_var("X_API_KEY", "my_api_key");
///
///     HttpServer::new(|| {
///         App::new()
///             .service(public_handler)
///             .service(auth)
///             .service(refresh_auth)
///             .service(x_api_key)
///     })
///     .bind(("127.0.0.1", 8080))?
///     .run()
///     .await
/// }
///
/// struct AppState {
///     app_name: String,
/// }
/// ```
///
/// # Important Considerations
///
/// *   **Error Handling:** The current implementation uses `unwrap_or("")` on the header value and `expect` for environment variables. For production, more robust error handling should be implemented (e.g., returning `HttpResponse::BadRequest` for malformed headers).
/// *   **Dependency:** This macro depends on the `nextera_utils::jwt` crate, which needs to be included in your `Cargo.toml`.
/// *   **Environment Variables:** Ensure `ACCESS_TOKEN_SECRET`, `REFRESH_TOKEN_SECRET` and `X_API_KEY` are set in your environment. Never hardcode secrets in your source code. Consider using a secrets management solution for production.
/// *   **HttpRequest Injection:** The macro automatically injects `actix_web::HttpRequest` as the first argument of the decorated function. Make sure your handler function signature is compatible.
/// *   **Async Functions:** This macro supports `async` functions.
#[proc_macro_attribute]
pub fn authentication(_args: TokenStream, input: TokenStream) -> TokenStream {
    let input_fn = parse_macro_input!(input as ItemFn);

    let fn_name = &input_fn.sig.ident;
    let fn_async_ness = &input_fn.sig.asyncness;
    let fn_visibility = &input_fn.vis;
    let fn_inputs = &input_fn.sig.inputs;
    let fn_output = &input_fn.sig.output;
    let fn_body = &input_fn.block;

    // Wrap the function logic with authentication logic
    let expanded = quote! {

        #fn_visibility #fn_async_ness fn #fn_name(
            actix_web_req: actix_web::HttpRequest, // Automatically inject HttpRequest
            #fn_inputs
        ) #fn_output {
            use actix_web::HttpResponse;

            // Get response language
            let default = actix_web::http::header::HeaderValue::from_static("en");
            let c = actix_web_req.headers().get("Content-Language").unwrap_or(&default).to_str().unwrap_or("en");
            let invalid_credentials = match c {
                "zh-CN" => "凭证无效",
                "th" => "ข้อมูลเข้าสู่ระบบไม่ถูกต้อง",
                "mm" => "အထောက်အထားများ မှားယွင်းနေပါသည်",
                _ => "Invalid credentials"
            };
            // Extract and validate the Authorization header
            if let Some(auth_header) = actix_web_req.headers().get("Authorization") {
                let token = auth_header.to_str().unwrap_or("").trim();

                // Ensure token starts with "Bearer "
                let token = token.trim_start_matches("Bearer ").trim();

                // Load environment variables
                let access_token_secret = std::env::var("ACCESS_TOKEN_SECRET")
                    .expect("Failed to get ACCESS_TOKEN_SECRET from environment");

                // Validate the token
                if nextera_utils::jwt::validate_jwt(token, &access_token_secret).is_err() {
                    return HttpResponse::Unauthorized().json(nextera_utils::models::response_message::ResponseMessage { message: String::from(invalid_credentials)});
                }
            } else {
                // Respond with Unauthorized if no Authorization header is present
                return HttpResponse::Unauthorized().json(nextera_utils::models::response_message::ResponseMessage { message: String::from(invalid_credentials)});
            }


            // Proceed with the original function body
            #fn_body
        }
    };

    TokenStream::from(expanded)
}

#[proc_macro_attribute]
pub fn refresh_authentication(_args: TokenStream, input: TokenStream) -> TokenStream {
    let input_fn = parse_macro_input!(input as ItemFn);

    let fn_name = &input_fn.sig.ident;
    let fn_async_ness = &input_fn.sig.asyncness;
    let fn_visibility = &input_fn.vis;
    let fn_inputs = &input_fn.sig.inputs;
    let fn_output = &input_fn.sig.output;
    let fn_body = &input_fn.block;

    // Wrap the function logic with refresh token authentication logic
    let expanded = quote! {

        #fn_visibility #fn_async_ness fn #fn_name(
            actix_web_req: actix_web::HttpRequest, // Automatically inject HttpRequest
            #fn_inputs
        ) #fn_output {
            use actix_web::HttpResponse;

            // Get response language
            let default = actix_web::http::header::HeaderValue::from_static("en");
            let c = actix_web_req.headers().get("Content-Language").unwrap_or(&default).to_str().unwrap_or("en");
            let invalid_credentials = match c {
                "zh-CN" => "凭证无效",
                "th" => "ข้อมูลเข้าสู่ระบบไม่ถูกต้อง",
                "mm" => "အထောက်အထားများ မှားယွင်းနေပါသည်",
                _ => "Invalid credentials"
            };

            // Extract and validate the Authorization header
            if let Some(auth_header) = actix_web_req.headers().get("Authorization") {
                let token = auth_header.to_str().unwrap_or("").trim();

                // Ensure token starts with "Bearer "
                let token = token.trim_start_matches("Bearer ").trim();

                // Load environment variables
                let refresh_token_secret = std::env::var("REFRESH_TOKEN_SECRET")
                    .expect("Failed to get REFRESH_TOKEN_SECRET from environment");

                // Validate the token
                if nextera_utils::jwt::validate_jwt(token, &refresh_token_secret).is_err() {
                    return HttpResponse::Unauthorized().json(nextera_utils::models::response_message::ResponseMessage { message: String::from(invalid_credentials)});
                }
            } else {
                // Respond with Unauthorized if no Authorization header is present
                return HttpResponse::Unauthorized().json(nextera_utils::models::response_message::ResponseMessage { message: String::from(invalid_credentials)});
            }

            // Proceed with the original function body
            #fn_body
        }
    };

    TokenStream::from(expanded)
}

#[proc_macro_attribute]
pub fn x_api_key(_args: TokenStream, input: TokenStream) -> TokenStream {
    let input_fn = parse_macro_input!(input as ItemFn);

    let fn_name = &input_fn.sig.ident;
    let fn_async_ness = &input_fn.sig.asyncness;
    let fn_visibility = &input_fn.vis;
    let fn_inputs = &input_fn.sig.inputs;
    let fn_output = &input_fn.sig.output;
    let fn_body = &input_fn.block;

    // Wrap the function logic with refresh token authentication logic
    let expanded = quote! {

        #fn_visibility #fn_async_ness fn #fn_name(
            actix_web_req: actix_web::HttpRequest, // Automatically inject HttpRequest
            #fn_inputs
        ) #fn_output {
            use actix_web::HttpResponse;

            // Get response language
            let default = actix_web::http::header::HeaderValue::from_static("en");
            let c = actix_web_req.headers().get("Content-Language").unwrap_or(&default).to_str().unwrap_or("en");
            let invalid_credentials = match c {
                "zh-CN" => "凭证无效",
                "th" => "ข้อมูลเข้าสู่ระบบไม่ถูกต้อง",
                "mm" => "အထောက်အထားများ မှားယွင်းနေပါသည်",
                _ => "Invalid API Key"
            };

            // Extract and validate the Authorization header
            if let Some(auth_header) = actix_web_req.headers().get("X-API-Key") {
                let xapikey = auth_header.to_str().unwrap_or("").trim();

                // Load environment variables
                let env_xapikey = std::env::var("X_API_KEY").expect("Failed to get X_API_KEY from environment");

                // Validate the token
                if xapikey.ne(&env_xapikey) {
                    return HttpResponse::Unauthorized().json(nextera_utils::models::response_message::ResponseMessage { message: String::from(invalid_credentials)});
                }
            } else {
                // Respond with Unauthorized if no Authorization header is present
                return HttpResponse::Unauthorized().json(nextera_utils::models::response_message::ResponseMessage { message: String::from(invalid_credentials)});
            }

            // Proceed with the original function body
            #fn_body
        }
    };

    TokenStream::from(expanded)
}
