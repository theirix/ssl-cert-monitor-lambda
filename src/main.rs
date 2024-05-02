mod cert;
mod error;

use lambda_runtime::{run, service_fn, tracing, Error, LambdaEvent};

use crate::cert::Validator;
use crate::error::MonitorError;
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_s3::Client;
use chrono::Utc;
use lambda_runtime::tracing::info;
use serde::{Deserialize, Serialize};
use std::str;
use url::Url;

/// Requests come into the runtime as unicode
/// strings in json format, which can map to any structure that implements `serde::Deserialize`
/// The runtime pays no attention to the contents of the request payload.
#[derive(Deserialize)]
struct Request {
    s3_config_location: String,
}

#[derive(Serialize)]
struct Status {
    domain: String,
    valid: bool,
    error: String,
}

/// The runtime requires responses to be serialized into json.
/// The runtime pays no attention to the contents of the response payload.
#[derive(Serialize)]
struct Response {
    req_id: String,
    statuses: Vec<Status>,
}

async fn parse_domains(s3_config_location: &str) -> Result<Vec<String>, Error> {
    let region_provider = RegionProviderChain::default_provider().or_else("us-east-1");
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(region_provider)
        .load()
        .await;
    let client = Client::new(&config);

    let url = Url::parse(s3_config_location).or(Err(MonitorError::Config(
        "Cannot parse S3 url ".to_owned() + s3_config_location,
    )))?;
    let bucket = url.domain().ok_or(MonitorError::Config(
        "Cannot parse S3 url ".to_owned() + s3_config_location,
    ))?;
    let object = url.path().trim_start_matches('/');

    info!(
        "Parse S3 config location {} to bucket: {}, url: {}",
        &s3_config_location, bucket, object
    );

    let object = client
        .get_object()
        .bucket(bucket)
        .key(object)
        .send()
        .await
        .map_err(Box::new)?;

    let content = object.body.collect().await?.to_vec();

    let lines: Vec<String> = str::from_utf8(&content)?
        .split('\n')
        .map(String::from)
        .collect();

    Ok(lines)
}

/// This is the main body for the function.
/// Write your code inside it.
/// There are some code example in the following URLs:
/// - https://github.com/awslabs/aws-lambda-rust-runtime/tree/main/examples
/// - https://github.com/aws-samples/serverless-rust-demo/
async fn function_handler(event: LambdaEvent<Request>) -> Result<Response, Error> {
    // Extract some useful info from the request
    let s3_config_location = event.payload.s3_config_location;

    let domains: Vec<String> = parse_domains(&s3_config_location).await?;

    let max_expiration: u64 = 10;

    let validator = Validator::new(Utc::now(), max_expiration);

    let statuses: Vec<Status> = domains
        .into_iter()
        .map(|domain| match validator.validate_domain(&domain) {
            Ok(()) => Status {
                domain: domain.to_string(),
                valid: true,
                error: String::new(),
            },
            Err(error) => Status {
                domain: domain.to_string(),
                valid: false,
                error: error.to_string(),
            },
        })
        .collect();

    // Prepare the response
    let resp = Response {
        req_id: event.context.request_id,
        statuses,
    };

    // Return `Response` (it will be serialized to JSON automatically by the runtime)
    Ok(resp)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing::init_default_subscriber();

    run(service_fn(function_handler)).await
}
