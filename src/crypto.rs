use chrono::{DateTime, SecondsFormat, Utc};
use data_encoding::HEXLOWER;
use ring::{
    digest::{Context, SHA256},
    hmac,
};

fn to_cred_datestamp(time: DateTime<Utc>) -> String {
    time.date_naive().format("%Y%m%d").to_string()
}

fn compute_scope(time: DateTime<Utc>, region: &str) -> String {
    format!(
        "{}/{}/cassandra/aws4_request",
        to_cred_datestamp(time),
        region
    )
}

fn sha256(input: &[u8]) -> String {
    let mut context = Context::new(&SHA256);
    context.update(input);
    HEXLOWER.encode(context.finish().as_ref())
}

fn form_cannonical_request(
    access_key_id: &str,
    scope: &str,
    time: DateTime<Utc>,
    nonce: &str,
) -> String {
    let nonce_hash = sha256(nonce.as_bytes());

    let query_string = &[
        "X-Amz-Algorithm=AWS4-HMAC-SHA256".to_string(),
        format!(
            "X-Amz-Credential={}%2F{}",
            access_key_id,
            scope.replace("/", "%2F")
        ),
        format!(
            "X-Amz-Date={}",
            time.to_rfc3339_opts(SecondsFormat::Millis, true)
                .replace(":", "%3A")
        ),
        "X-Amz-Expires=900".to_string(),
    ]
    .join("&")
    .to_string();

    format!(
        "PUT\n/authenticate\n{}\nhost:cassandra\n\nhost\n{}",
        query_string, nonce_hash
    )
}

fn hmac(data: &str, key_value: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, &key_value);
    hmac::sign(&key, data.as_bytes()).as_ref().to_vec()
}

fn derive_signing_key(secret: &str, time: DateTime<Utc>, region: &str) -> Vec<u8> {
    let s = format!("AWS4{}", secret);
    let h = hmac(&to_cred_datestamp(time), s.as_bytes());
    let h = hmac(region, &h);
    let h = hmac("cassandra", &h);
    let h = hmac("aws4_request", &h);
    h
}

fn create_signature(
    canonical_request: &str,
    t: DateTime<Utc>,
    signing_scope: &str,
    signing_key: &[u8],
) -> String {
    let digest = sha256(canonical_request.as_bytes());
    let s = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        t.to_rfc3339_opts(SecondsFormat::Millis, true),
        signing_scope,
        digest
    );
    return HEXLOWER.encode(&hmac(&s, signing_key));
}

pub fn build_signed_response(
    region: &str,
    nonce: &str,
    access_key_id: &str,
    secret: &str,
    session_token: Option<&str>,
    t: DateTime<Utc>,
) -> String {
    let scope = compute_scope(t, region);
    let canonical_request = form_cannonical_request(access_key_id, &scope, t, nonce);
    let signing_key = derive_signing_key(secret, t, region);
    let signature = create_signature(&canonical_request, t, &scope, &signing_key);
    let mut result = format!(
        "signature={},access_key={},amzdate={}",
        signature,
        access_key_id,
        t.to_rfc3339_opts(SecondsFormat::Millis, true)
    );

    if let Some(session_token) = session_token {
        result = format!("{},session_token={}", result, session_token);
    }

    result
}
