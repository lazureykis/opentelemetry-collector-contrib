# Azure Key Vault Basic Auth Extension

| Status        |           |
| ------------- |-----------|
| Stability     | [development] |
| Distributions | [contrib] |

This extension provides [Basic Auth](https://datatracker.ietf.org/doc/html/rfc7617) credentials for outbound HTTP and gRPC requests. Credentials are fetched from [Azure Key Vault](https://azure.microsoft.com/en-us/products/key-vault/) and rotated in place at a configurable interval without restarting the collector.

## Configuration

```yaml
extensions:
  azurekeyvaultbasicauth:
    vault_url: "https://my-vault.vault.azure.net"
    secret_name: "my-creds"
    secret_version: ""          # optional — default "" means latest version
    refresh_interval: 30m       # optional — default 1h
    username_key: "username"    # optional — default "username"
    password_key: "password"    # optional — default "password"

exporters:
  otlphttp:
    endpoint: "https://ingest.example.com"
    auth:
      authenticator: azurekeyvaultbasicauth

service:
  extensions: [azurekeyvaultbasicauth]
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

Uses [DefaultAzureCredential](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azidentity#DefaultAzureCredential), which automatically tries managed identity, environment variables, workload identity, Azure CLI, and other credential sources in order.
