# Testing

Service-agnostic testing patterns for reliable, maintainable test suites.

---

## Unit Testing Services in Isolation

Test orchestration logic independently of all I/O.

- Mock every dependency that performs network, database, or filesystem I/O
- Focus unit tests on: branching logic, error handling, partial failure scenarios, data transformation
- Keep tests fast (< 10ms each) — no real HTTP calls, no database

```typescript
describe('OrganisationService.create', () => {
  it('returns partial success when registry step fails', async () => {
    identityClient.create.mockResolvedValue({ ok: true, id: 'abc' });
    registryClient.register.mockRejectedValue(new Error('timeout'));

    const result = await service.create({ name: 'Acme' });

    expect(result.steps.identity.status).toBe('success');
    expect(result.steps.registry.status).toBe('failed');
  });
});
```

---

## Integration Tests Against Real Modules

Spin up the full application module with stubbed network boundaries.

- Use the framework's testing module (e.g. NestJS `Test.createTestingModule`) to wire the real DI graph
- Stub only the outermost HTTP/DB layer — all internal wiring runs for real
- Assert end-to-end request/response contracts: status code, body shape, headers
- Seed test state through the API, not by manipulating internal state directly

---

## Contract Testing

Snapshot the expected interface of each external API dependency.

- Define the expected request/response shape for each external call your service makes
- Run contract checks in CI so upstream breaking changes are caught before deployment
- Use tools like Pact (consumer-driven contracts) or OpenAPI diff for REST services
- Treat a failing contract check as a blocker, not a warning

---

## HTTP Interception

Simulate external service behaviour without running real infrastructure.

- Use request-level interceptors (nock, MSW, WireMock, `httptest` in Go) to intercept outbound HTTP
- Cover the full failure surface: success, timeout, 4xx, 5xx, malformed response
- Assert that your service handles each failure mode correctly without network access

```typescript
nock('https://api.example.com')
  .post('/organisations')
  .replyWithError({ code: 'ECONNRESET' });

await expect(service.create(dto)).resolves.toMatchObject({
  steps: { registry: { status: 'failed' } }
});
```

---

## Test Data Factories

Reusable, composable builders for request/response fixtures.

- Create factory functions or builder classes for each domain object
- Apply sensible defaults; allow per-test overrides for only the fields that matter
- Avoid copy-pasted raw JSON objects scattered across test files
- Share factories between unit and integration tests

```typescript
const organisationFactory = (overrides = {}) => ({
  name: 'Test Organisation',
  type: 'care-provider',
  active: true,
  ...overrides,
});
```

---

## References

- [Pact (Consumer-Driven Contracts)](https://pact.io)
- [nock (Node.js HTTP mocking)](https://github.com/nock/nock)
- [MSW (Mock Service Worker)](https://mswjs.io)
- [WireMock](https://wiremock.org)
