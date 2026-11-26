use std::collections::HashMap;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::StatusCode;
use hyper::header::{CACHE_CONTROL, LOCATION};
use serde_json::{Value, json};
use url::Url;
use wiremock::matchers::{body_string, header, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use angos_cache::Config as CacheConfig;
use angos_secret::Secret;
use angos_transport::ResponseBody;

use super::*;
use crate::auth::oidc::validator::tests::build_test_provider_config;
use crate::command::server::handlers::{handle_ui_authorize, handle_ui_token};

const REDIRECT_URI: &str = "https://registry.example.com/";

fn sign_in_config(client_secret: Option<&str>) -> UiOidcConfig {
    UiOidcConfig {
        provider: "forgejo".to_string(),
        client_id: "angos-ui".to_string(),
        client_secret: client_secret.map(|secret| Secret::new(secret.to_string())),
        scopes: "openid profile groups".to_string(),
        exchange_setting: None,
        share_session: false,
    }
}

/// A provider whose discovery document names `issuer` and advertises `methods`.
async fn provider(issuer: &str, methods: Value) -> MockServer {
    let server = MockServer::start().await;
    let uri = server.uri();
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "issuer": issuer.replace("{uri}", &uri),
            "jwks_uri": format!("{uri}/login/oauth/keys"),
            "authorization_endpoint": format!("{uri}/login/oauth/authorize?tenant=main"),
            "token_endpoint": format!("{uri}/login/oauth/access_token"),
            "token_endpoint_auth_methods_supported": methods,
        })))
        .mount(&server)
        .await;
    server
}

fn sign_in(server: &MockServer, issuer: &str, client_secret: Option<&str>) -> UiSignIn {
    let provider = oidc::Config {
        jwks_uri: None,
        ..build_test_provider_config(&issuer.replace("{uri}", &server.uri()))
    };
    let cache = CacheConfig::Memory.to_backend().unwrap();
    UiSignIn::new("forgejo", &provider, &sign_in_config(client_secret), &cache).unwrap()
}

fn exchange() -> CodeExchange {
    CodeExchange {
        code: "the-code".to_string(),
        code_verifier: "the-verifier".to_string(),
        redirect_uri: REDIRECT_URI.to_string(),
    }
}

/// The browser's values ride through; the client, scopes and PKCE method are
/// the registry's own, and the endpoint keeps a query it already carries.
#[tokio::test]
async fn the_authorization_url_carries_the_request_and_the_client() {
    let server = provider("{uri}", json!([])).await;
    let sign_in = sign_in(&server, "{uri}", Some("secret"));

    let url = sign_in
        .authorization_url(&AuthorizationRequest {
            redirect_uri: REDIRECT_URI.to_string(),
            state: "the-state".to_string(),
            nonce: "the-nonce".to_string(),
            code_challenge: "the-challenge".to_string(),
        })
        .await
        .unwrap();

    assert_eq!(url.path(), "/login/oauth/authorize");
    let query: HashMap<String, String> = url.query_pairs().into_owned().collect();
    let expected: HashMap<String, String> = [
        ("tenant", "main"),
        ("response_type", "code"),
        ("client_id", "angos-ui"),
        ("redirect_uri", REDIRECT_URI),
        ("scope", "openid profile groups"),
        ("state", "the-state"),
        ("nonce", "the-nonce"),
        ("code_challenge", "the-challenge"),
        ("code_challenge_method", "S256"),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_string(), value.to_string()))
    .collect();
    assert_eq!(query, expected);
}

/// Gitea spells its issuer with a trailing slash; OIDC Discovery drops it
/// before appending the well-known suffix, while `iss` keeps it.
#[tokio::test]
async fn an_issuer_with_a_trailing_slash_is_discovered_without_a_double_slash() {
    let server = provider("{uri}/", json!([])).await;
    let sign_in = sign_in(&server, "{uri}/", None);

    let url = sign_in
        .authorization_url(&AuthorizationRequest {
            redirect_uri: REDIRECT_URI.to_string(),
            state: "s".to_string(),
            nonce: "n".to_string(),
            code_challenge: "c".to_string(),
        })
        .await;

    assert!(url.is_ok(), "{url:?}");
}

/// A document naming another issuer is the provider's misconfiguration, not a
/// credential the browser presented, so it must not answer 401.
#[tokio::test]
async fn a_mismatched_issuer_is_the_provider_failing() {
    let server = provider("https://elsewhere.example.com", json!([])).await;
    let sign_in = sign_in(&server, "{uri}", None);

    let result = sign_in.exchange_code(&exchange()).await;

    assert!(
        matches!(result, Err(Error::ProviderUnavailable(_))),
        "{result:?}"
    );
}

/// A Basic header unless the provider offers only `client_secret_post`; a
/// public client sends its id alone. Only the ID token reaches the browser.
#[tokio::test]
async fn the_code_is_redeemed_with_the_client_credentials_the_provider_takes() {
    let base = "grant_type=authorization_code&code=the-code\
                &redirect_uri=https%3A%2F%2Fregistry.example.com%2F&code_verifier=the-verifier";
    let basic = format!("Basic {}", BASE64_STANDARD.encode("angos-ui:s%2Fcret"));
    for (secret, methods, body, authorization) in [
        (
            Some("s/cret"),
            json!([]),
            base.to_string(),
            Some(basic.clone()),
        ),
        (
            Some("s/cret"),
            json!(["client_secret_basic", "client_secret_post"]),
            base.to_string(),
            Some(basic.clone()),
        ),
        (
            Some("s/cret"),
            json!(["client_secret_post"]),
            format!("{base}&client_id=angos-ui&client_secret=s%2Fcret"),
            None,
        ),
        (None, json!([]), format!("{base}&client_id=angos-ui"), None),
    ] {
        let server = provider("{uri}", methods.clone()).await;
        let expected_authorization = authorization.clone();
        Mock::given(method("POST"))
            .and(path("/login/oauth/access_token"))
            .and(header("content-type", "application/x-www-form-urlencoded"))
            .and(body_string(body.clone()))
            .and(move |request: &Request| {
                request
                    .headers
                    .get("authorization")
                    .map(|value| value.to_str().unwrap().to_string())
                    == expected_authorization
            })
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "provider-access-token",
                "refresh_token": "provider-refresh-token",
                "id_token": "the-id-token",
            })))
            .expect(1)
            .mount(&server)
            .await;

        let token = sign_in(&server, "{uri}", secret)
            .exchange_code(&exchange())
            .await
            .unwrap_or_else(|e| panic!("{methods} with secret {secret:?}: {e:?}"));

        assert_eq!(
            serde_json::to_value(&token).unwrap(),
            json!({ "id_token": "the-id-token" })
        );
    }
}

/// A refusal is the browser's failed sign-in and says why; a provider that
/// fails or answers without an ID token is unavailable.
#[tokio::test]
async fn a_failed_exchange_is_a_refusal_or_the_provider_failing() {
    for (status, body, refused) in [
        (
            400,
            json!({"error": "invalid_grant", "error_description": "code expired"}),
            Some("the provider refused the code: invalid_grant: code expired"),
        ),
        (
            401,
            json!({"error": "invalid_client"}),
            Some("the provider refused the code: invalid_client"),
        ),
        (500, json!({}), None),
        (200, json!({"access_token": "no-id-token"}), None),
    ] {
        let server = provider("{uri}", json!([])).await;
        Mock::given(method("POST"))
            .and(path("/login/oauth/access_token"))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .mount(&server)
            .await;

        let result = sign_in(&server, "{uri}", None)
            .exchange_code(&exchange())
            .await;

        match refused {
            Some(reason) => {
                assert!(
                    matches!(&result, Err(Error::BadRequest(msg)) if msg == reason),
                    "HTTP {status}: {result:?}"
                );
            }
            None => assert!(
                matches!(result, Err(Error::ProviderUnavailable(_))),
                "HTTP {status}: {result:?}"
            ),
        }
    }
}

/// Not configured is a miss, a malformed request a 400, and the redirect is
/// never cached: it carries the browser's one-time state.
#[tokio::test]
async fn the_authorize_handler_redirects_to_the_provider() {
    let server = provider("{uri}", json!([])).await;
    let sign_in = sign_in(&server, "{uri}", None);
    let query =
        "redirect_uri=https%3A%2F%2Fregistry.example.com%2F&state=s&nonce=n&code_challenge=c";

    let unconfigured = handle_ui_authorize(None, Some(query)).await;
    assert!(
        matches!(unconfigured, Err(Error::NotFound(_))),
        "{unconfigured:?}"
    );
    let malformed = handle_ui_authorize(Some(&sign_in), Some("state=s")).await;
    assert!(
        matches!(malformed, Err(Error::BadRequest(_))),
        "{malformed:?}"
    );

    let response = handle_ui_authorize(Some(&sign_in), Some(query))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    let location = Url::parse(response.headers()[LOCATION].to_str().unwrap()).unwrap();
    assert_eq!(
        format!(
            "{}{}",
            location.origin().ascii_serialization(),
            location.path()
        ),
        format!("{}/login/oauth/authorize", server.uri())
    );
}

/// The answer is a bearer credential, so no cache may keep it, and a form
/// larger than the cap is refused before anything reaches the provider.
#[tokio::test]
async fn the_token_handler_answers_the_id_token_uncached() {
    let server = provider("{uri}", json!([])).await;
    Mock::given(method("POST"))
        .and(path("/login/oauth/access_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id_token": "the-id-token"})))
        .expect(1)
        .mount(&server)
        .await;
    let sign_in = sign_in(&server, "{uri}", None);
    let form = "code=the-code&code_verifier=v&redirect_uri=https%3A%2F%2Fregistry.example.com%2F";

    let oversized =
        handle_ui_token(Some(&sign_in), Full::new(Bytes::from(form.repeat(1000)))).await;
    assert!(
        matches!(oversized, Err(Error::BadRequest(_))),
        "{oversized:?}"
    );

    let response = handle_ui_token(Some(&sign_in), Full::new(Bytes::from(form)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
    let ResponseBody::Fixed(body) = response.into_body() else {
        panic!("expected a fixed body");
    };
    let body: Value = serde_json::from_slice(&body.collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body, json!({"id_token": "the-id-token"}));
}
