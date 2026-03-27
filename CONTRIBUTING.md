# Contributing to k8s-egress-guard

Thank you for your interest in contributing! This document explains how to get started.

## Reporting Issues

- Search [existing issues](../../issues) before opening a new one.
- Include Go version, OS, and reproduction steps.
- For security vulnerabilities, **do not open a public issue** — email the maintainer directly.

## Development Setup

**Prerequisites:** Go 1.21+

```bash
git clone https://github.com/rtoma/k8s-egress-guard.git
cd k8s-egress-guard
go mod download
```

Run all tests:

```bash
go test ./...
```

Run with the example config:

```bash
CONFIGMAP_PATH=./egress-policy.yaml LOG_LEVEL=DEBUG go run cmd/main.go
```

## Submitting a Pull Request

1. Fork the repository and create a branch from `main`.
2. Make your changes, following the conventions below.
3. Add or update tests to cover your changes.
4. Run `go test ./...` and `go vet ./...` — both must pass.
5. Format your code with `gofmt -w .`.
6. Open a PR with a clear description of what it changes and why.

## Code Conventions

- Follow standard Go idioms and [Effective Go](https://go.dev/doc/effective_go).
- Format all code with `gofmt`.
- Keep packages focused: `internal/config`, `internal/proxy`, `internal/logging`, `internal/metrics`.
- Write tests alongside the code in `_test.go` files; end-to-end tests go in `e2e/`.
- Prefer structured logging via `internal/logging` over `fmt.Print*`.
- Do not log sensitive values (API keys, credentials, TLS material).

## License

By submitting a pull request, you agree that your contribution is licensed under the [Apache 2.0 License](LICENSE).
