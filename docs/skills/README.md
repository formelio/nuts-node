# Engineering Skills

Service-agnostic engineering patterns applicable across all projects and services.

## Contents

| File | Description |
|---|---|
| [architecture-design.md](./architecture-design.md) | Distributed system design: dual-write, API contracts, domain modelling, config |
| [backend.md](./backend.md) | Layered architecture, error handling, DTOs, startup validation |
| [testing.md](./testing.md) | Unit, integration, contract, HTTP interception, test data factories |
| [frontend.md](./frontend.md) | Server-state management, form architecture, schema sharing, accessibility |
| [observability.md](./observability.md) | Correlation IDs, structured logging, health probes, feature flags |
| [developer-experience.md](./developer-experience.md) | Shared packages, client generation, linting, local environment parity |

## Principles

These skills are intentionally **technology-agnostic**. The patterns apply regardless of:

- **Language**: TypeScript, Go, Rust, Java, Python
- **Framework**: NestJS, Express, Gin, Axum, Spring
- **Infrastructure**: cloud provider, container runtime, message broker
- **Domain**: healthcare, identity, registry, or any other service

Concrete examples use common tools for illustration only — adapt them to the stack in use.
