# GCP Secret Manager Basic Auth Extension

| Status        |           |
| ------------- |-----------|
| Stability     | [development] |
| Distributions | [contrib] |

This extension provides [Basic Auth](https://datatracker.ietf.org/doc/html/rfc7617) credentials for outbound HTTP and gRPC requests. Credentials are fetched from [GCP Secret Manager](https://cloud.google.com/secret-manager) and rotated in place at a configurable interval without restarting the collector.

## Configuration

```yaml
extensions:
  gcpsecretsmanagerbasicauth:
    secret_name: "projects/my-project/secrets/my-creds/versions/latest"
    refresh_interval: 30m      # optional — default 1h
    username_key: "username"   # optional — default "username"
    password_key: "password"   # optional — default "password"

exporters:
  otlphttp:
    endpoint: "https://ingest.example.com"
    auth:
      authenticator: gcpsecretsmanagerbasicauth

service:
  extensions: [gcpsecretsmanagerbasicauth]
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

Uses [Application Default Credentials (ADC)](https://cloud.google.com/docs/authentication/application-default-credentials): `GOOGLE_APPLICATION_CREDENTIALS` environment variable, GCE metadata server, or `gcloud auth application-default login`.
