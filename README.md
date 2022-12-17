# scylla-aws-keyspaces-authenticator

This crate provides a simple to use AuthenticatorProvider implementation for scylla crate that works with AWS KeySpaces for Cassandra service.

[![Crates.io](https://img.shields.io/crates/v/scylla-aws-keyspaces-authenticator)](https://crates.io/crates/scylla-aws-keyspaces-authenticator) ![Crates.io](https://img.shields.io/crates/l/scylla-aws-keyspaces-authenticator) [![docs.rs](https://img.shields.io/docsrs/scylla-aws-keyspaces-authenticator)](https://docs.rs/scylla-aws-keyspaces-authenticator)

## Usage:
```rust
use scylla::SessionBuilder;
use scylla_aws_keyspaces_authenticator::AwsKeyspacesAuthenticator;
use openssl::ssl::*;

let config = aws_config::from_env().region("us-east-1").load().await;

// One-liner to enable AWS Sigv4 authentication for Scylla driver for Rust:
let authenticator = AwsKeyspacesAuthenticator::new(config);

// Some SSL setup
let mut ssl_context = SslContextBuilder::new(SslMethod::tls()).unwrap();
ssl_context.set_certificate_file("./examples/aws-keyspaces-cert.pem", SslFiletype::PEM).unwrap();
ssl_context.set_verify(SslVerifyMode::NONE);

// Create session
let session = SessionBuilder::new()
    .known_node("cassandra.us-east-1.amazonaws.com:9142")
    .authenticator_provider(authenticator)
    .ssl_context(Some(ssl_context.build()))
    .build()
    .await
    .unwrap();

// Run query
let results = session.query("SELECT * from example.example_table;", &[]).await.unwrap();
println!("{:?}", results);
```
