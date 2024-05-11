# SSL Cert Monitor

A suite of AWS Lambda functions to monitor domain certificates with close expiration date.

## Buid

Project uses experimental [Rust Lambda runtime](https://github.com/awslabs/aws-lambda-rust-runtime). It includes function code and AWS Lambda Runtime into one binary that is build locally.

To build, use `cargo-lambda` plugin:

    cargo lambda build --release

or

	  cargo lambda build --release --arm64

It creates a bundled `bootrstap` binaries for both functions. To deploy lambdas, execute

    cargo lambda deploy --iam-role $EXECROLE --binary-name ssl-cert-monitor-lambda
    cargo lambda deploy --iam-role $EXECROLE --binary-name ssl-cert-reporter-lambda

To launch the moinitor lambda:

    aws lambda invoke --cli-binary-format raw-in-base64-out --function-name ssl-cert-monitor-lambda --payload '{"s3_config_location": "s3://BUCKET/path/to/config.txt"}' output.json && jq < output.json

Reporting lambda collects output from the monitor lambda and produce a succeeded check:

```json
{"report": {"Valid": null} }
```

or for failed checks:

```json
{ "report": { "Invalid": "Found 1 issues.\nDomain expired.example (network error: invalid peer certificate: Expired)" } }
```

## AWS Integration

It's handy to use these lambdas together with AWS Step Functions workflow. There are two pre-configured SNS topics - for expiration message and for errors. The whole workflow is invoked daily with AWS EventBridge Scheduler.

![stepfunctions](docs/stepfunctions.svg)



## License

BSD 3-Clause
