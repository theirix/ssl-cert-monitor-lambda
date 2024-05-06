use lambda_runtime::{run, service_fn, tracing, Error, LambdaEvent};

use lambda_runtime::tracing::info;
use serde::{Deserialize, Serialize};

/// Requests come into the runtime as unicode
/// strings in json format, which can map to any structure that implements `serde::Deserialize`
/// The runtime pays no attention to the contents of the request payload.
#[derive(Deserialize)]
struct Request {
    #[allow(dead_code)]
    req_id: String,
    statuses: Vec<Status>,
}

#[derive(Deserialize)]
struct Status {
    domain: String,
    valid: bool,
    error: String,
}

#[derive(Serialize)]
enum Report {
    Valid(()),
    Invalid(String)
}

/// The runtime requires responses to be serialized into json.
/// The runtime pays no attention to the contents of the response payload.
#[derive(Serialize)]
struct Response {
    report: Report
}

fn aggregate(statuses: Vec<Status>) -> Result<Report, Error> {
    let invalid_statuses: Vec<Status> = statuses
        .into_iter()
        .filter(|status| !status.valid)
        .collect();

    if invalid_statuses.is_empty() {
        info!("Everything is fine");
        Ok(Report::Valid(()))
    } else {
        let message = format!("Found {} issues.\n", invalid_statuses.len())
            + &invalid_statuses
                .into_iter()
                .map(|status| format!("Domain {} ({})", status.domain, status.error))
                .collect::<Vec<_>>()
                .join("\n");
        info!("Composed message {}", &message);
        Ok(Report::Invalid(message))
    }
}

/// This is the main body for the function.
/// Write your code inside it.
/// There are some code example in the following URLs:
/// - https://github.com/awslabs/aws-lambda-rust-runtime/tree/main/examples
/// - https://github.com/aws-samples/serverless-rust-demo/
async fn function_handler(event: LambdaEvent<Request>) -> Result<Response, Error> {
    // Extract some useful info from the request
    let report = aggregate(event.payload.statuses)?;

    // Prepare the response
    let resp = Response { report };

    // Return `Response` (it will be serialized to JSON automatically by the runtime)
    Ok(resp)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing::init_default_subscriber();

    run(service_fn(function_handler)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aggregate_empty() {
        let report = aggregate(vec![]).expect("should succeed");
        assert!(matches!(report, Report::Valid(())));
    }

    #[test]
    fn test_aggregate_one() {
        let report = aggregate(vec![Status {
            domain: "foobar".into(),
            valid: false,
            error: "oops".into(),
        }]).expect("should succeed");
        match report {
            Report::Valid(_) => assert!(false),
            Report::Invalid(s) => assert_eq!(s, "Found 1 issues.\nDomain foobar (oops)")
        }
    }

    #[test]
    fn test_aggregate_mixed() {
        let report = aggregate(vec![
            Status {
                domain: "foobar".into(),
                valid: false,
                error: "oops".into(),
            },
            Status {
                domain: "baz".into(),
                valid: true,
                error: "".into(),
            },
        ])
        .expect("should succeed");
        match report {
            Report::Valid(_) => assert!(false),
            Report::Invalid(s) => assert_eq!(s, "Found 1 issues.\nDomain foobar (oops)")
        }
    }
}
