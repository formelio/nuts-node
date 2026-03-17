# Architecture & Design

Service-agnostic patterns for building reliable, maintainable distributed systems.

---

## Dual-Write & Multi-System Consistency

Know when best-effort parallel writes are acceptable vs. when you need saga choreography, outbox pattern, or compensating transactions.

- Use **parallel best-effort writes** for non-critical fan-out (analytics, audit logs)
- Use **saga choreography** when multi-step distributed transactions require rollback semantics
- Use the **outbox pattern** to guarantee at-least-once delivery to downstream services without distributed locks
- Design response contracts that communicate partial success explicitly (e.g. `207 Multi-Status` with per-system step results)

```json
// Example partial success envelope
{
  "status": 207,
  "results": [
    { "service": "identity", "status": "success", "id": "abc123" },
    { "service": "registry", "status": "failed", "error": "timeout" }
  ]
}
```

---

## API Contract Design

Spec-first development ensures the interface is stable before implementation begins.

- Write the OpenAPI spec before writing code
- Auto-generate specs from code annotations as a fallback, but review the output
- Version contracts explicitly (`/v1/`, `/v2/`) and treat breaking changes as deployable events
- Use `x-` extensions sparingly; prefer standard fields when possible

---

## Domain Data Modelling

Separate internal domain types from external API shapes to insulate the core from schema drift.

- Define **domain types** that represent your business concepts
- Define **API DTOs** that represent what external consumers see
- Maintain explicit mapping layers (assemblers/transformers) between the two
- External schema changes should only require updating the mapping layer, not the core domain

```
ExternalDTO  →  [Mapper]  →  DomainModel  →  [Mapper]  →  PersistenceEntity
```

---

## Configuration-Driven Behaviour

Express environment topology as structured, validated config rather than scattered env vars.

- Group related config into namespaced objects (e.g. `auth.issuerUrl`, `registry.baseUrl`)
- Validate all required config at **startup**, not at first use
- Use typed config classes (e.g. NestJS `ConfigService`, Go `viper`) with schema validation
- Never hardcode service addresses, vendor identifiers, or feature states in code

---

## References

- [Saga Pattern (microservices.io)](https://microservices.io/patterns/data/saga.html)
- [Outbox Pattern (microservices.io)](https://microservices.io/patterns/data/transactional-outbox.html)
- [OpenAPI Specification](https://spec.openapis.org/oas/latest.html)
