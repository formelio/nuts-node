# Observability & Operations

Service-agnostic patterns for making systems understandable and operable in production.

---

## Correlation IDs

Propagate a single request ID through all downstream calls.

- Generate a UUID at the entry point (API gateway or first service) if none is present
- Propagate via a standard header (e.g. `X-Correlation-ID`, `traceparent`)
- Include the correlation ID in every log line emitted during that request
- Return it in response headers so clients can reference it in support tickets
- In async flows (queues, background jobs), carry the ID in the message envelope

```
Client → Gateway (X-Correlation-ID: abc123)
    → Service A (propagates abc123)
        → Service B (propagates abc123)
            → Database (logged with abc123)
```

---

## Structured Logging

Log as JSON with consistent fields; avoid string interpolation.

| Field | Description |
|---|---|
| `level` | `debug`, `info`, `warn`, `error` |
| `timestamp` | ISO 8601 UTC |
| `correlationId` | Request correlation ID |
| `service` | Service name and version |
| `message` | Human-readable summary |
| `duration` | Elapsed time in ms (for timed operations) |
| `error` | Structured error object (not stringified stack trace) |

```json
{
  "level": "info",
  "timestamp": "2026-03-17T10:00:00.000Z",
  "correlationId": "abc123",
  "service": "organisation-service@1.2.0",
  "message": "Organisation created",
  "duration": 142,
  "organisationId": "org-456"
}
```

---

## Health and Readiness Probes

Expose endpoints that verify each external dependency individually.

- **Liveness** (`/health/live`): is the process running? Return `200` unless the process is deadlocked or corrupted
- **Readiness** (`/health/ready`): can the service handle traffic? Check each dependency (HTTP service, DB, cache, broker)
- Return per-dependency status in the response body for operator visibility
- Never return `200` from readiness if a critical dependency is unreachable

```json
GET /health/ready → 503
{
  "status": "degraded",
  "checks": {
    "database":      { "status": "ok" },
    "identity-service": { "status": "unreachable", "latency": null },
    "cache":         { "status": "ok" }
  }
}
```

---

## Feature Flags

Gate new functionality behind runtime flags rather than deploys.

- Use a feature flag service (LaunchDarkly, Unleash, GrowthBook, or simple env-based flags) to decouple releasing from deploying
- Dark-launch new API endpoints or behaviours to a subset of traffic before full rollout
- Allow instant rollback by toggling a flag rather than reverting a deployment
- Document each flag: what it controls, who owns it, when it should be removed

```typescript
if (featureFlags.isEnabled('new-organisation-flow', context)) {
  return newOrganisationService.create(dto);
}
return legacyOrganisationService.create(dto);
```

---

## References

- [OpenTelemetry](https://opentelemetry.io)
- [W3C Trace Context (traceparent)](https://www.w3.org/TR/trace-context/)
- [Unleash (open-source feature flags)](https://www.getunleash.io)
- [The Twelve-Factor App — Logs](https://12factor.net/logs)
