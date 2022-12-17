//! This crate provides a simple to use AuthenticatorProvider implementation for scylla crate that works with AWS KeySpaces for Cassandra service.
//!
//! Usage:
//! ```no_run
//!# async fn example() {
//! use scylla::SessionBuilder;
//! use scylla_aws_keyspaces_authenticator::AwsKeyspacesAuthenticator;
//! use openssl::ssl::*;
//!
//! let config = aws_config::from_env().region("us-east-1").load().await;
//!
//! // One-liner to enable AWS Sigv4 authentication for Scylla driver for Rust:
//! let authenticator = AwsKeyspacesAuthenticator::new(config);
//!
//! // Some SSL setup
//! let mut ssl_context = SslContextBuilder::new(SslMethod::tls()).unwrap();
//! ssl_context.set_certificate_file("./examples/aws-keyspaces-cert.pem", SslFiletype::PEM).unwrap();
//! ssl_context.set_verify(SslVerifyMode::NONE);
//!
//! // Create session
//! let session = SessionBuilder::new()
//!     .known_node("cassandra.us-east-1.amazonaws.com:9142")
//!     .authenticator_provider(authenticator)
//!     .ssl_context(Some(ssl_context.build()))
//!     .build()
//!     .await
//!     .unwrap();
//!
//! // Run query
//! let results = session.query("SELECT * from example.example_table;", &[]).await.unwrap();
//! println!("{:?}", results);
//!# }
//! ```
use std::sync::Arc;

use aws_config::SdkConfig;
use aws_types::credentials::ProvideCredentials;

use chrono::Utc;
use scylla::authentication::{AuthError, AuthenticatorProvider, AuthenticatorSession};

mod crypto;

/// AuthenticatorProvider implementation for AWS KeySpaces for Cassandra.
pub struct AwsKeyspacesAuthenticator {
    sdk_config: SdkConfig,
}

impl AwsKeyspacesAuthenticator {
    pub fn new(sdk_config: SdkConfig) -> Arc<AwsKeyspacesAuthenticator> {
        Arc::new(AwsKeyspacesAuthenticator { sdk_config })
    }
}

#[async_trait::async_trait]
impl AuthenticatorProvider for AwsKeyspacesAuthenticator {
    async fn start_authentication_session(
        &self,
        _authenticator_name: &str,
    ) -> Result<(Option<Vec<u8>>, Box<dyn AuthenticatorSession>), AuthError> {
        Ok((
            Some(b"SigV4\000\000".to_vec()),
            Box::new(AwsKeyspacesAuthenticatorSession {
                sdk_config: self.sdk_config.clone(),
            }),
        ))
    }
}

struct AwsKeyspacesAuthenticatorSession {
    sdk_config: SdkConfig,
}

#[async_trait::async_trait]
impl AuthenticatorSession for AwsKeyspacesAuthenticatorSession {
    async fn evaluate_challenge(
        &mut self,
        token: Option<&[u8]>,
    ) -> Result<Option<Vec<u8>>, AuthError> {
        let nonce = match token {
            Some(token) => extract_nonce(token)?,
            None => {
                return Err("Expected nonce".to_string());
            }
        };

        let region = match self.sdk_config.region() {
            Some(r) => r.to_string(),
            None => {
                return Err("Region must be defined in aws_config::SdkConfig object.".to_string());
            }
        };

        match self.sdk_config.credentials_provider() {
            Some(credentials_provider) => match credentials_provider.provide_credentials().await {
                Ok(credentials) => {
                    let response = crypto::build_signed_response(
                        &region,
                        &nonce,
                        credentials.access_key_id(),
                        credentials.secret_access_key(),
                        credentials.session_token(),
                        Utc::now(),
                    );
                    Ok(Some(response.as_bytes().to_vec()))
                }
                Err(err) => Err(format!("Cannot get AWS credentials: {:?}", err)),
            },
            None => {
                Err("aws_config::SdkConfig does not deliver any credentials provider.".to_string())
            }
        }
    }

    async fn success(&mut self, _token: Option<&[u8]>) -> Result<(), AuthError> {
        Ok(())
    }
}

fn extract_nonce(payload: &[u8]) -> Result<String, AuthError> {
    let string = String::from_utf8(payload.to_vec())
        .map_err(|e| format!("Expected utf-8 challange: {:?}", e))?;

    if !string.starts_with("nonce=") {
        return Err("Expected \"nonce=\" in challange.".to_string());
    }

    Ok(string[6..].to_string())
}
