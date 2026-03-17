# Developer Experience

Service-agnostic patterns for keeping development fast, consistent, and low-friction.

---

## Monorepo Shared Packages

Extract shared types, constants, and validation schemas into a common package.

- Publish a `@org/shared` (or equivalent) package consumed by all services and frontends
- Include: API DTOs, validation schemas, error codes, shared constants
- Keep the shared package free of runtime dependencies on any specific framework
- Consuming services import from the shared package — schema changes propagate automatically at compile time

```
packages/
  shared/
    src/
      dtos/          ← request/response shapes
      schemas/       ← Zod / class-validator schemas
      errors/        ← error codes and types
services/
  organisation-api/  ← imports @org/shared
  member-api/        ← imports @org/shared
frontend/            ← imports @org/shared
```

---

## OpenAPI Client Generation

Generate typed HTTP client code from the API spec rather than hand-writing fetch calls.

- Use tools like `openapi-typescript` (types only), `orval`, or `openapi-generator` to generate clients
- Run generation as part of the build or as a pre-commit hook
- API schema changes surface as TypeScript/compile errors rather than runtime surprises
- Clients include: typed request/response interfaces, error types, and query parameter shapes

```bash
# Example: generate types from a spec
npx openapi-typescript ./api/openapi.yaml -o ./src/generated/api.d.ts
```

---

## Linting & Formatting as CI Gates

Enforce consistent style, import order, and no unused exports at the PR level.

- Run `eslint`, `prettier`, `golangci-lint`, `clippy` (or equivalent) in CI — fail the build on violations
- Enforce no-unused-exports / dead code detection to keep the codebase lean
- Use consistent import ordering rules to reduce diff noise in reviews
- Autofix safe violations in pre-commit hooks; fail unsafe violations explicitly

```yaml
# Example CI step
- name: Lint
  run: npm run lint && npm run type-check
```

---

## Local Environment Parity

Developers should be able to run the full dependency graph locally without manual setup.

- Provide a `docker-compose.yml` (or equivalent) that mirrors production topology
- Include all required external services: databases, identity providers, message brokers, dependent APIs
- Document the single command to start everything: `make dev`, `docker compose up`, etc.
- Use health checks in compose so dependent services wait for their dependencies to be ready

```yaml
# docker-compose.yml excerpt
services:
  db:
    image: postgres:16
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
  api:
    build: .
    depends_on:
      db:
        condition: service_healthy
```

---

## References

- [Turborepo (monorepo tooling)](https://turbo.build)
- [orval (OpenAPI client generation)](https://orval.dev)
- [openapi-typescript](https://openapi-ts.dev)
- [ESLint](https://eslint.org)
- [golangci-lint](https://golangci-lint.run)
