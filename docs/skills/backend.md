# Backend

Service-agnostic patterns for building clean, testable, and maintainable backend services.

---

## Layered Service Architecture

Each layer has a single, well-defined responsibility.

```
HTTP Layer (Controllers)
    ↓  validates input, maps HTTP to domain calls
Service Layer (Business Logic)
    ↓  orchestrates use cases, handles branching and errors
Client Layer (External I/O)
    ↓  wraps all remote calls (HTTP, DB, message broker)
```

- **Controllers** own HTTP concerns only: routing, parsing, status codes, response shaping
- **Services** own orchestration: calling clients, applying business rules, handling partial failure
- **Client services** own external I/O: retries, circuit breaking, timeout configuration
- Each layer is independently unit-testable with mocks at the layer boundary

---

## Structured Error Reporting

Model failures as data rather than exceptions wherever possible.

- Use result envelopes (`StepResult[]`, `{ ok, error }`) for expected failure paths
- Reserve exceptions for truly unexpected runtime errors
- Let callers decide how to surface errors — services should not assume the rendering context
- Include enough context in errors for a caller to act: error code, affected resource, suggested action

```typescript
// Prefer
type StepResult<T> = { ok: true; data: T } | { ok: false; error: AppError };

// Over
function doThing(): T {
  throw new SomeServiceException('...');
}
```

---

## Centralised Cross-Cutting Concerns

Use middleware, interceptors, and filters instead of duplicating logic per controller.

| Concern | Mechanism |
|---|---|
| Request correlation IDs | Middleware (inject + propagate) |
| Response envelope shaping | Interceptor |
| Exception → HTTP status mapping | Exception filter / error handler |
| Auth / JWT validation | Guard / middleware |
| Request logging | Middleware |

---

## Startup Validation

Assert required config, connectivity, and schema correctness at boot.

- Check all required environment variables / config keys are present and non-empty
- Run a lightweight connectivity probe for each external dependency (HTTP ping, DB connection)
- Fail fast with a clear error message — don't let misconfiguration cause mysterious runtime failures
- Use readiness probes to delay traffic until startup checks pass

---

## DTO Design

Validate at system boundaries; never trust external input.

- Use declarative validation (`class-validator`, Zod, `go-playground/validator`) on all incoming DTOs
- Share or generate schemas from a single source across layers to keep validation in sync
- Strip unknown fields by default (`whitelist: true` in NestJS, `DisallowUnknownFields` in Go)
- Return validation errors with field-level detail, not just a generic `400 Bad Request`

```typescript
class CreateOrganisationDto {
  @IsString()
  @MinLength(2)
  name: string;

  @IsUrl()
  @IsOptional()
  website?: string;
}
```

---

## References

- [NestJS Layers (Controllers, Providers)](https://docs.nestjs.com/controllers)
- [go-playground/validator](https://github.com/go-playground/validator)
- [Zod](https://zod.dev)
