use serde::{Deserialize, Serialize};

use angos_secret::Secret;

#[derive(Clone, Debug, Deserialize)]
pub struct UiConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "UiConfig::default_name")]
    pub name: String,
    #[serde(default)]
    pub oidc: Option<UiOidcConfig>,
}

/// How the UI signs a browser in. The issuer is not repeated here: it is read
/// from the named `auth.oidc` provider, so the browser can only be sent to an
/// issuer the registry validates tokens from.
#[derive(Clone, Debug, Deserialize)]
pub struct UiOidcConfig {
    pub provider: String,
    pub client_id: String,
    /// Set for a confidential client, which takes the `registry` exchange: the
    /// secret never reaches the browser.
    #[serde(default)]
    pub client_secret: Option<Secret<String>>,
    #[serde(default = "UiOidcConfig::default_scopes")]
    pub scopes: String,
    /// Who redeems the authorization code. Read through
    /// [`UiOidcConfig::exchange`], which settles the default.
    #[serde(default, rename = "exchange")]
    pub exchange_setting: Option<TokenExchange>,
    /// Keep the sign-in in local storage, shared by every tab and window until
    /// the token expires, instead of the tab's own session storage.
    #[serde(default)]
    pub share_session: bool,
}

/// Where the UI's authorization code is redeemed.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenExchange {
    /// The browser calls the provider's discovery and token endpoints itself,
    /// which takes a public client and CORS at the provider.
    Browser,
    /// The registry runs the provider side, server to server: no CORS needed,
    /// and a confidential client's secret stays with the registry.
    Registry,
}

impl Default for UiConfig {
    fn default() -> Self {
        UiConfig {
            enabled: false,
            name: UiConfig::default_name(),
            oidc: None,
        }
    }
}

impl UiConfig {
    fn default_name() -> String {
        "Angos".to_string()
    }
}

impl UiOidcConfig {
    /// The OAuth `scope` parameter, verbatim. `openid` is what makes the
    /// authorization request an OIDC one and yields the ID token the UI sends.
    fn default_scopes() -> String {
        "openid profile email".to_string()
    }

    /// The configured exchange, else `registry` for a client holding a secret,
    /// which only the registry can use, and `browser` for a public one.
    #[must_use]
    pub fn exchange(&self) -> TokenExchange {
        self.exchange_setting.unwrap_or(match self.client_secret {
            Some(_) => TokenExchange::Registry,
            None => TokenExchange::Browser,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::configuration::UiConfig;
    use crate::configuration::ui::TokenExchange;

    fn sign_in(extra: &str) -> super::UiOidcConfig {
        let config: UiConfig = toml::from_str(&format!(
            r#"
            enabled = true
            [oidc]
            provider = "dex"
            client_id = "angos-ui"
            {extra}
            "#
        ))
        .unwrap();
        config.oidc.unwrap()
    }

    #[test]
    fn oidc_defaults_to_the_openid_scopes() {
        assert_eq!(sign_in("").scopes, "openid profile email");
    }

    /// A public client keeps the browser exchange it always had; a secret can
    /// only be used by the registry, so it implies the registry exchange.
    #[test]
    fn the_exchange_defaults_by_the_kind_of_client() {
        for (extra, expected) in [
            ("", TokenExchange::Browser),
            (r#"client_secret = "s""#, TokenExchange::Registry),
            (r#"exchange = "registry""#, TokenExchange::Registry),
            (
                "client_secret = \"s\"\nexchange = \"registry\"",
                TokenExchange::Registry,
            ),
        ] {
            assert_eq!(sign_in(extra).exchange(), expected, "{extra}");
        }
    }
}
