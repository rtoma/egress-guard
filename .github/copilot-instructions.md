# Copilot Chat Instructions for k8s-egress-guard

A lightweight egress proxy for Kubernetes that enforces zero-trust networking by restricting outbound pod traffic to verified destinations. Product requirements document is available (ask if needed)

## Implementation

We use Golang for this project. Follow idiomatic Go practices and leverage standard libraries where possible.

## How to edit .go files

- When editing .go files, ALWAYS ensure standard 'gofmt' formatting.
- Do not use incremental edits if the file is under 200 lines; rewrite the whole file instead to prevent range corruption.
- Ensure every file has exactly one 'package' declaration at the very top.
- Maintain Unix-style line endings (\n).

### Package Structure

Main entry point in `cmd/main.go` and packages under `internal/`.

### Kubernetes Deployment

This project is deployed on Kubernetes, but deployment manifests are outside the scope of this codebase.

### Unit testing requirements

Suggest to create unit tests using Go's testing package, focus on core logic and edge cases.

Do not aim for 100% coverage at the expense of code quality.

Unit tests are stored alongside the code in _test.go files.

### End-to-End testing requirements

End-to-end tests are stored in the `e2e/` directory.

## When Helping

- Suggest idiomatic Go patterns and best practices
- Propose error handling strategies
- Guide on testing approaches
- Recommend relevant Go libraries (e.g., fasthttp, go-chi, prometheus client)
- Help with Kubernetes integration
- Suggest security improvements
- Help optimize performance

## When NOT to Help

- Implementing unrelated features
- Compromising security requirements
- Cutting corners on error handling
- Skipping logging/observability
