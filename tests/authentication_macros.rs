use actix_web::{test, web, App, Responder};
use nextera_jwt::{authentication, refresh_authentication, x_api_key};
use nextera_utils::jwt;

#[authentication]
async fn protected_handler(_: actix_web::HttpRequest) -> impl Responder {
    HttpResponse::Ok().body("Access token validated")
}

#[refresh_authentication]
async fn refresh_handler(_: actix_web::HttpRequest) -> impl Responder {
    HttpResponse::Ok().body("Refresh token validated")
}

#[x_api_key]
async fn api_key_handler(_: actix_web::HttpRequest) -> impl Responder {
    HttpResponse::Ok().body("API key validated")
}

#[actix_web::test]
async fn test_protected_handler_valid_token() {
    std::env::set_var("ACCESS_TOKEN_SECRET", "test_access_secret");
    std::env::set_var("JWT_AUDIENCE", "test_jwt_audience");

    let app =
        test::init_service(App::new().route("/protected", web::get().to(protected_handler))).await;

    let (token, _) = jwt::generate_jwt(
        1,
        1,
        "test_access_secret",
        3600,
        "session_uuid",
        "test_jwt_audience",
    )
    .expect("Failed to generate access token");

    let req = test::TestRequest::get()
        .uri("/protected")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
}

#[actix_web::test]
async fn test_protected_handler_invalid_token() {
    std::env::set_var("ACCESS_TOKEN_SECRET", "test_access_secret");

    let app =
        test::init_service(App::new().route("/protected", web::get().to(protected_handler))).await;

    let req = test::TestRequest::get()
        .uri("/protected")
        .insert_header(("Authorization", "Bearer invalid_token"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}

#[actix_web::test]
async fn test_api_key_handler_valid_key() {
    std::env::set_var("X_API_KEY", "test_api_key");

    let app = test::init_service(App::new().route("/apikey", web::get().to(api_key_handler))).await;

    let req = test::TestRequest::get()
        .uri("/apikey")
        .insert_header(("X-API-Key", "test_api_key"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200);
}

#[actix_web::test]
async fn test_api_key_handler_invalid_key() {
    std::env::set_var("X_API_KEY", "test_api_key");

    let app = test::init_service(App::new().route("/apikey", web::get().to(api_key_handler))).await;

    let req = test::TestRequest::get()
        .uri("/apikey")
        .insert_header(("X-API-Key", "wrong_key"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}
