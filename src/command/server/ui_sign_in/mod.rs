//! The web UI's sign-in, run against the provider by the registry on the
//! browser's behalf. Discovery and the code exchange happen server to server,
//! so a provider serving no CORS headers (Forgejo, Gitea) works, and a
//! confidential client's secret never reaches the browser.

use std::fmt::Display;
use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use tracing::warn;
use url::Url;
use url::form_urlencoded::{Serializer, byte_serialize};

use angos_cache::Cache;
use angos_secret::Secret;

use crate::auth::Error as AuthError;
use crate::auth::authenticator::build_oidc_client;
use crate::auth::oidc;
use crate::auth::oidc::validator::{SignInEndpoints, fetch_sign_in_endpoints};
use crate::command::server::error::Error;
use crate::configuration::UiOidcConfig;

/// What the browser sends to start a sign-in: where the provider returns it,
/// the values it checks on return, and the S256 PKCE challenge.
#[derive(Debug, Deserialize)]
pub struct AuthorizationRequest {
    pub redirect_uri: String,
    pub state: String,
    pub nonce: String,
    pub code_challenge: String,
}

/// What the browser sends to finish a sign-in the provider redirected back from.
#[derive(Debug, Deserialize)]
pub struct CodeExchange {
    pub code: String,
    pub code_verifier: String,
    pub redirect_uri: String,
}

/// The only part of the provider's token response handed to the browser: the
/// access and refresh tokens would let it act at the provider as the user.
#[derive(Debug, Deserialize, Serialize)]
pub struct SignInToken {
    pub id_token: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
}

/// An RFC 6749 error answer.
#[derive(Deserialize)]
struct TokenError {
    error: String,
    error_description: Option<String>,
}

pub struct UiSignIn {
    provider: oidc::Config,
    client_id: String,
    client_secret: Option<Secret<String>>,
    scopes: String,
    client: Client,
    cache: Arc<Cache>,
}

impl UiSignIn {
    pub fn new(
        provider_name: &str,
        provider: &oidc::Config,
        sign_in: &UiOidcConfig,
        cache: &Arc<Cache>,
    ) -> Result<Self, Error> {
        Ok(Self {
            provider: provider.clone(),
            client_id: sign_in.client_id.clone(),
            client_secret: sign_in.client_secret.clone(),
            scopes: sign_in.scopes.clone(),
            client: build_oidc_client(provider_name, provider)?,
            cache: Arc::clone(cache),
        })
    }

    /// The provider's authorization URL for `request`, to redirect the browser to.
    pub async fn authorization_url(&self, request: &AuthorizationRequest) -> Result<Url, Error> {
        let endpoints = self.endpoints().await?;
        let mut url = Url::parse(&endpoints.authorization_endpoint).map_err(|e| {
            Error::ProviderUnavailable(format!(
                "invalid authorization_endpoint {}: {e}",
                endpoints.authorization_endpoint
            ))
        })?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &request.redirect_uri)
            .append_pair("scope", &self.scopes)
            .append_pair("state", &request.state)
            .append_pair("nonce", &request.nonce)
            .append_pair("code_challenge", &request.code_challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(url)
    }

    /// Redeems an authorization code at the provider's token endpoint.
    ///
    /// The secret goes in a Basic header, which OIDC assumes of a provider
    /// advertising no methods, unless the provider offers `client_secret_post`
    /// alone. A refusal is the browser's failed sign-in and answers 400 with
    /// the provider's reason; anything else is the provider's failure.
    pub async fn exchange_code(&self, exchange: &CodeExchange) -> Result<SignInToken, Error> {
        let endpoints = self.endpoints().await?;
        let token_endpoint = &endpoints.token_endpoint;

        // Built whole before the first await: the serializer is not `Send`.
        let request = {
            let mut form = Serializer::new(String::new());
            form.append_pair("grant_type", "authorization_code")
                .append_pair("code", &exchange.code)
                .append_pair("redirect_uri", &exchange.redirect_uri)
                .append_pair("code_verifier", &exchange.code_verifier);
            let mut request = self
                .client
                .post(token_endpoint)
                .header(ACCEPT, "application/json")
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .timeout(Duration::from_secs(self.provider.http_request_timeout_secs));

            let methods = &endpoints.token_endpoint_auth_methods_supported;
            let posts_secret = methods.iter().any(|method| method == "client_secret_post")
                && !methods.iter().any(|method| method == "client_secret_basic");
            match &self.client_secret {
                Some(secret) if !posts_secret => {
                    // RFC 6749 2.3.1 form-encodes both halves before they are joined.
                    let username: String = byte_serialize(self.client_id.as_bytes()).collect();
                    let password: String = byte_serialize(secret.expose().as_bytes()).collect();
                    request = request.basic_auth(username, Some(password));
                }
                Some(secret) => {
                    form.append_pair("client_id", &self.client_id)
                        .append_pair("client_secret", secret.expose());
                }
                None => {
                    form.append_pair("client_id", &self.client_id);
                }
            }
            request.body(form.finish())
        };

        let unavailable =
            |e: &dyn Display| Error::ProviderUnavailable(format!("{token_endpoint}: {e}"));
        let response = request.send().await.map_err(|e| unavailable(&e))?;
        let status = response.status();
        let body = response.bytes().await.map_err(|e| unavailable(&e))?;

        if status.is_client_error() {
            let reason = match serde_json::from_slice::<TokenError>(&body) {
                Ok(TokenError {
                    error,
                    error_description: Some(description),
                }) => format!("{error}: {description}"),
                Ok(TokenError { error, .. }) => error,
                Err(_) => format!("HTTP {status}"),
            };
            warn!("{token_endpoint} refused a UI sign-in: {reason}");
            return Err(Error::BadRequest(format!(
                "the provider refused the code: {reason}"
            )));
        }
        if !status.is_success() {
            return Err(unavailable(&format!("HTTP {status}")));
        }

        match serde_json::from_slice::<TokenResponse>(&body) {
            Ok(TokenResponse {
                id_token: Some(id_token),
            }) => Ok(SignInToken { id_token }),
            Ok(TokenResponse { id_token: None }) => Err(unavailable(
                &"no ID token was returned; is `openid` among the scopes?",
            )),
            Err(e) => Err(unavailable(&e)),
        }
    }

    /// Discovery has no credential of the caller's to refuse, so whatever fails
    /// it, a mismatched issuer included, is the provider's failure.
    async fn endpoints(&self) -> Result<SignInEndpoints, Error> {
        fetch_sign_in_endpoints(&self.provider, &self.client, &self.cache)
            .await
            .map_err(|e| match e {
                AuthError::Unauthorized(msg) => Error::ProviderUnavailable(msg),
                e => Error::from(e),
            })
    }
}

#[cfg(test)]
mod tests;
