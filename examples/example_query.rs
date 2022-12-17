use openssl::ssl::{SslContextBuilder, SslFiletype, SslMethod, SslVerifyMode};
use scylla::SessionBuilder;
use scylla_aws_keyspaces_authenticator::AwsKeyspacesAuthenticator;

#[tokio::main]
async fn main() {
    let config = aws_config::from_env().region("us-east-1").load().await;

    let authenticator = AwsKeyspacesAuthenticator::new(config);

    let mut context_builder = SslContextBuilder::new(SslMethod::tls()).unwrap();
    context_builder
        .set_certificate_file("./examples/aws-keyspaces-cert.pem", SslFiletype::PEM)
        .unwrap();
    context_builder.set_verify(SslVerifyMode::NONE);

    let session = SessionBuilder::new()
        .known_node("cassandra.us-east-1.amazonaws.com:9142")
        .authenticator_provider(authenticator)
        .ssl_context(Some(context_builder.build()))
        .build()
        .await
        .expect("Cannot create session");

    let results = session
        .query("SELECT * from example.example_table;", &[])
        .await
        .expect("Cannot execute query");
    println!("{:#?}", results);
}
