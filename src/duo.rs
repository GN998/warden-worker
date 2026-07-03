use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, KeyInit, Mac};
use serde_json::Value;
use sha2::{Sha256, Sha512};
use worker::{Env, Fetch, Headers, Method, Request, RequestInit};

use crate::crypto::ct_eq;
use crate::error::AppError;
use crate::models::{device::Device, user::User};

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;
const DUO_OIDC_EXPIRE_SECONDS: i64 = 300;
const CLIENT_ASSERTION_TYPE: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// Validates the Duo configuration values to prevent misconfigurations.
/// Length checks match the official Duo Universal SDK examples (20 for ID, 40 for Secret).
fn validate_duo_config_values(client_id: &str, client_secret: &str, host: &str) -> Result<(), AppError> {
    if client_id.len() != 20 {
        return Err(AppError::BadRequest("Invalid Duo client id length; expected 20 characters".to_string()));
    }
    if client_secret.len() != 40 {
        return Err(AppError::BadRequest("Invalid Duo client secret length; expected 40 characters".to_string()));
    }
    if !host.starts_with("api-")
        || !(host.ends_with(".duosecurity.com") || host.ends_with(".duofederal.com"))
    {
        return Err(AppError::BadRequest("Invalid Duo API host; expected api-*.duosecurity.com or api-*.duofederal.com".to_string()));
    }
    Ok(())
}

fn b64url_json(value: &serde_json::Value) -> Result<String, AppError> {
    let bytes = serde_json::to_vec(value).map_err(|_| AppError::Internal)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn b64url_bytes(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn sign_hs256(secret: &str, msg: &str) -> Result<String, AppError> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| AppError::Crypto("Invalid Duo client secret".to_string()))?;
    mac.update(msg.as_bytes());
    Ok(b64url_bytes(&mac.finalize().into_bytes()))
}

fn sign_hs512(secret: &str, msg: &str) -> Result<String, AppError> {
    let mut mac = HmacSha512::new_from_slice(secret.as_bytes())
        .map_err(|_| AppError::Crypto("Invalid Duo client secret".to_string()))?;

    mac.update(msg.as_bytes());

    Ok(b64url_bytes(&mac.finalize().into_bytes()))
}

fn jwt_hs512(secret: &str, payload: serde_json::Value) -> Result<String, AppError> {
    let header = serde_json::json!({
        "typ": "JWT",
        "alg": "HS512"
    });

    let encoded_header = b64url_json(&header)?;
    let encoded_payload = b64url_json(&payload)?;
    let signing_input = format!("{}.{}", encoded_header, encoded_payload);
    let signature = sign_hs512(secret, &signing_input)?;

    Ok(format!("{}.{}", signing_input, signature))
}

fn verify_jwt_hs512(secret: &str, token: &str) -> Result<Value, AppError> {
    let parts: Vec<&str> = token.split('.').collect();

    if parts.len() != 3 {
        return Err(AppError::BadRequest("Invalid JWT format".to_string()));
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let expected_sig = sign_hs512(secret, &signing_input)?;

    if !ct_eq(parts[2], &expected_sig) {
        return Err(AppError::BadRequest("Invalid JWT signature".to_string()));
    }

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| AppError::BadRequest("Invalid JWT payload".to_string()))?;

    serde_json::from_slice::<Value>(&payload_bytes)
        .map_err(|_| AppError::BadRequest("Invalid JWT payload json".to_string()))
}

fn jwt_hs256(secret: &str, payload: serde_json::Value) -> Result<String, AppError> {
    let header = serde_json::json!({
        "typ": "JWT",
        "alg": "HS256"
    });
    let encoded_header = b64url_json(&header)?;
    let encoded_payload = b64url_json(&payload)?;
    let signing_input = format!("{}.{}", encoded_header, encoded_payload);
    let signature = sign_hs256(secret, &signing_input)?;
    Ok(format!("{}.{}", signing_input, signature))
}

fn verify_jwt_hs256(secret: &str, token: &str) -> Result<Value, AppError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AppError::BadRequest("Invalid JWT format".to_string()));
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let expected_sig = sign_hs256(secret, &signing_input)?;
    if !ct_eq(parts[2], &expected_sig) {
        return Err(AppError::BadRequest("Invalid JWT signature".to_string()));
    }
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| AppError::BadRequest("Invalid JWT payload".to_string()))?;
    serde_json::from_slice::<Value>(&payload_bytes)
        .map_err(|_| AppError::BadRequest("Invalid JWT payload json".to_string()))
}

fn duo_client_id(env: &Env) -> Result<String, AppError> {
    env.var("DUO_CLIENT_ID")
        .or_else(|_| env.var("DUO_IKEY"))
        .map_err(|_| AppError::BadRequest("DUO_CLIENT_ID/DUO_IKEY not configured".to_string()))
        .map(|v| v.to_string().trim().to_string())
}

fn duo_client_secret(env: &Env) -> Result<String, AppError> {
    env.secret("DUO_CLIENT_SECRET")
        .or_else(|_| env.secret("DUO_SKEY"))
        .or_else(|_| env.var("DUO_CLIENT_SECRET"))
        .or_else(|_| env.var("DUO_SKEY"))
        .map_err(|_| {
            AppError::BadRequest("DUO_CLIENT_SECRET/DUO_SKEY not configured".to_string())
        })
        .map(|v| v.to_string().trim().to_string())
}

fn duo_host(env: &Env) -> Result<String, AppError> {
    env.var("DUO_HOST")
        .map_err(|_| AppError::BadRequest("DUO_HOST not configured".to_string()))
        .map(|v| v.to_string().trim().to_string())
}

fn web_vault_url(env: &Env) -> Result<String, AppError> {
    env.var("WEB_VAULT_URL")
        .or_else(|_| env.var("DOMAIN"))
        .map_err(|_| AppError::BadRequest("WEB_VAULT_URL/DOMAIN not configured".to_string()))
        .map(|v| v.to_string().trim_end_matches('/').to_string())
}

fn duo_redirect_uri(env: &Env) -> Result<String, AppError> {
    // Keep this compatible with Web Vault Duo Admin Panel Redirect URIs.
    Ok(format!("{}/duo-redirect.html?client=web", web_vault_url(env)?))
}

fn generate_state(env: &Env, user: &User, device: &Device) -> Result<String, AppError> {
    let secret = env.secret("JWT_SECRET")?.to_string();
    let now = chrono::Utc::now().timestamp();
    jwt_hs256(
        &secret,
        serde_json::json!({
            "user_id": user.id,
            "email": user.email,
            "device_identifier": device.identifier,
            "exp": now + DUO_OIDC_EXPIRE_SECONDS,
            "jti": uuid::Uuid::new_v4().to_string()
        }),
    )
}

fn verify_state(env: &Env, user: &User, device: &Device, state: &str) -> Result<(), AppError> {
    let secret = env.secret("JWT_SECRET")?.to_string();
    let claims = verify_jwt_hs256(&secret, state)?;
    let now = chrono::Utc::now().timestamp();
    let exp = claims
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| AppError::BadRequest("Invalid Duo state exp".to_string()))?;
    if now >= exp {
        return Err(AppError::BadRequest("Duo state expired".to_string()));
    }
    if claims.get("user_id").and_then(|v| v.as_str()) != Some(user.id.as_str()) {
        return Err(AppError::BadRequest("Duo state user mismatch".to_string()));
    }
    if claims.get("email").and_then(|v| v.as_str()) != Some(user.email.as_str()) {
        return Err(AppError::BadRequest("Duo state email mismatch".to_string()));
    }
    if claims
        .get("device_identifier")
        .and_then(|v| v.as_str())
        != Some(device.identifier.as_str())
    {
        return Err(AppError::BadRequest("Duo state device mismatch".to_string()));
    }
    Ok(())
}

/// Generate the Web Vault compatible AuthUrl for Duo Universal Prompt.
///
/// The returned URL points to Web Vault's duo-redirect.html. That connector
/// redirects the browser to the embedded Duo authorize URL.
pub fn generate_auth_url(env: &Env, user: &User, device: &Device) -> Result<String, AppError> {
    let client_id = duo_client_id(env)?;
    let client_secret = duo_client_secret(env)?;
    let host = duo_host(env)?;

    validate_duo_config_values(&client_id, &client_secret, &host)?;

    let redirect_uri = duo_redirect_uri(env)?;
    let state = generate_state(env, user, device)?;
    let now = chrono::Utc::now().timestamp();
    
    let request_jwt = jwt_hs512(
        &client_secret,
        serde_json::json!({
            "response_type": "code",
            "scope": "openid",
            "exp": now + DUO_OIDC_EXPIRE_SECONDS,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "duo_uname": user.email,
            "aud": format!("https://{}", host),
            "iss": client_id,
            "use_duo_code_attribute": false
        }),
    )?;
    
    let duo_authorize_url = format!(
        "https://{}/oauth/v1/authorize?response_type=code&client_id={}&redirect_uri={}&scope=openid&state={}&request={}",
        host,
        urlencoding::encode(&client_id),
        urlencoding::encode(&redirect_uri),
        urlencoding::encode(&state),
        urlencoding::encode(&request_jwt),
    );
    
    Ok(format!(
        "{}/duo-redirect.html?duoFramelessUrl={}",
        web_vault_url(env)?,
        urlencoding::encode(&duo_authorize_url)
    ))
}

/// Verify Web Vault Duo Universal Prompt result.
///
/// Handles multiple possible format inputs of Web Vault's twoFactorToken submission safely.
fn parse_duo_two_factor_token(two_factor_token: &str) -> Result<(String, String), AppError> {
    let raw = two_factor_token.trim();

    // Format 1: code|state
    if let Some((code, state)) = raw.split_once('|') {
        let code = code.trim();
        let state = state.trim();

        if !code.is_empty() && !state.is_empty() {
            return Ok((code.to_string(), state.to_string()));
        }
    }

    // Format 2: JSON string, e.g. {"code":"...","state":"..."}
    if let Ok(value) = serde_json::from_str::<Value>(raw) {
        let code = value
            .get("code")
            .or_else(|| value.get("Code"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty());

        let state = value
            .get("state")
            .or_else(|| value.get("State"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty());

        if let (Some(code), Some(state)) = (code, state) {
            return Ok((code.to_string(), state.to_string()));
        }
    }

    // Format 3: query-string style, e.g. code=...&state=...
    if raw.contains("code=") && raw.contains("state=") {
        let mut code: Option<String> = None;
        let mut state: Option<String> = None;

        for pair in raw.split('&') {
            if let Some((key, value)) = pair.split_once('=') {
                let decoded = urlencoding::decode(value)
                    .map_err(|_| AppError::BadRequest("Invalid Duo token encoding".to_string()))?
                    .to_string();

                match key {
                    "code" => code = Some(decoded),
                    "state" => state = Some(decoded),
                    _ => {}
                }
            }
        }

        if let (Some(code), Some(state)) = (code, state) {
            let code = code.trim();
            let state = state.trim();

            if !code.is_empty() && !state.is_empty() {
                return Ok((code.to_string(), state.to_string()));
            }
        }
    }

    Err(AppError::BadRequest("Invalid Duo token format".to_string()))
}

/// Safely exchange OIDC codes and verify ID token against the Duo backend.
pub async fn verify_auth_response(
    env: &Env,
    user: &User,
    device: &Device,
    two_factor_token: &str,
) -> Result<bool, AppError> {
    let (code, state) = parse_duo_two_factor_token(two_factor_token)?;

    if let Err(e) = verify_state(env, user, device, &state) {
        log::warn!("Duo state validation failed: {:?}", e);
        return Err(e);
    }
    
    let client_id = duo_client_id(env)?;
    let client_secret = duo_client_secret(env)?;
    let host = duo_host(env)?;

    validate_duo_config_values(&client_id, &client_secret, &host)?;

    let redirect_uri = duo_redirect_uri(env)?;
    let token_url = format!("https://{}/oauth/v1/token", host);
    let now = chrono::Utc::now().timestamp();
    
    let client_assertion = jwt_hs512(
        &client_secret,
        serde_json::json!({
            "iss": client_id,
            "sub": client_id,
            "aud": token_url,
            "exp": now + DUO_OIDC_EXPIRE_SECONDS,
            "iat": now,
            "jti": uuid::Uuid::new_v4().to_string()
        }),
    )?;
    
    let body = serde_urlencoded::to_string(&[
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
        ("client_assertion_type", CLIENT_ASSERTION_TYPE),
        ("client_assertion", client_assertion.as_str()),
        ("client_id", client_id.as_str()),
    ])
    .map_err(|_| AppError::Internal)?;
    
    let headers = Headers::new();
    headers.set("content-type", "application/x-www-form-urlencoded")?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post);
    init.with_headers(headers);
    init.with_body(Some(body.into()));
    
    let request = Request::new_with_init(&token_url, &init)?;
    let mut response = Fetch::Request(request)
        .send()
        .await
        .map_err(|_| AppError::BadRequest("Duo token exchange failed".to_string()))?;
        
    if !(200..300).contains(&response.status_code()) {
        let status = response.status_code();
        let body_text = response
            .text()
            .await
            .unwrap_or_else(|_| "<unable to read body>".to_string());
        
        let parsed: serde_json::Value =
            serde_json::from_str(&body_text).unwrap_or_else(|_| serde_json::json!({}));
            
        let error = parsed
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("<unknown>");
            
        let error_description = parsed
            .get("error_description")
            .and_then(|v| v.as_str())
            .unwrap_or("");
            
        log::warn!(
            "Duo token exchange failed: status={}, error={}, description={}",
            status,
            error,
            error_description
        );
        return Ok(false);
    }
    
    let token_json: Value = response
        .json()
        .await
        .map_err(|_| AppError::BadRequest("Invalid Duo token response".to_string()))?;
        
    let id_token = token_json
        .get("id_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::BadRequest("Duo response missing id_token".to_string()))?;
        
    let id_claims = match verify_jwt_hs512(&client_secret, id_token) {
        Ok(claims) => claims,
        Err(e) => {
            log::warn!("Duo id_token validation failed: {:?}", e);
            return Ok(false);
        }
    };

    if id_claims.get("aud").and_then(|v| v.as_str()) != Some(client_id.as_str()) {
        log::warn!("Duo id_token audience mismatch");
        return Ok(false);
    }
    
    if let Some(exp) = id_claims.get("exp").and_then(|v| v.as_i64()) {
        if chrono::Utc::now().timestamp() >= exp {
            log::warn!("Duo id_token expired");
            return Ok(false);
        }
    }
    
    let duo_user = id_claims
        .get("preferred_username")
        .or_else(|| id_claims.get("email"))
        .or_else(|| id_claims.get("sub"))
        .and_then(|v| v.as_str());
        
    if let Some(duo_user) = duo_user {
        if !ct_eq(&duo_user.to_lowercase(), &user.email.to_lowercase()) {
            log::warn!("Duo username mismatch");
            return Ok(false);
        }
    }
    
    Ok(true)
}