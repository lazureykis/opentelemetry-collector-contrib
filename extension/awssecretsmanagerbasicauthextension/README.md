# AWS Secrets Manager Basic Auth Extension

| Status        |           |
| ------------- |-----------|
| Stability     | [development] |
| Distributions | [contrib] |

This extension provides [Basic Auth](https://datatracker.ietf.org/doc/html/rfc7617) credentials for outbound HTTP and gRPC requests. Credentials are fetched from [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/) and rotated in place at a configurable interval without restarting the collector.

## Configuration

```yaml
extensions:
  awssecretsmanagerbasicauth:
    secret_arn: "arn:aws:secretsmanager:us-east-1:123456789012:secret:my-creds"
    region: "us-east-1"        # optional — uses AWS SDK default chain if omitted
    refresh_interval: 30m      # optional — default 1h
    username_key: "username"   # optional — default "username"
    password_key: "password"   # optional — default "password"

exporters:
  otlphttp:
    endpoint: "https://ingest.example.com"
    auth:
      authenticator: awssecretsmanagerbasicauth

service:
  extensions: [awssecretsmanagerbasicauth]
  pipelines:
    traces:
      exporters: [otlphttp]
```

## Secret Format

```json
{"username": "myuser", "password": "mypassword"}
```

Use `username_key` and `password_key` to configure different field names.

## Authentication

Uses the [AWS SDK default credential chain](https://docs.aws.amazon.com/sdk-for-go/v2/developer-guide/configure-gosdk.html): environment variables, `~/.aws/credentials`, IAM instance profiles, etc.
