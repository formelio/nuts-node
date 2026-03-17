# Frontend

Service-agnostic patterns for building reliable, accessible, and maintainable frontend applications.

---

## Server-State Management

Use a dedicated server-state library for all remote data.

- Use React Query, SWR, or equivalent — never hand-roll `useState` + `useEffect` for remote data
- Get caching, background refresh, loading/error states, and optimistic updates for free
- Separate **server state** (remote data) from **client state** (UI-only, e.g. modal open/closed)
- Use query keys that encode all cache-busting dimensions (e.g. `['organisations', orgId, 'members']`)

```typescript
const { data, isLoading, error } = useQuery({
  queryKey: ['organisations', orgId],
  queryFn: () => organisationApi.getById(orgId),
});
```

---

## Form Architecture

Schema-first forms where the validation schema is the single source of truth.

- Use `react-hook-form` + Zod (or equivalent) — the schema drives field rules, type inference, and error messages
- Never duplicate validation logic between form and submit handler
- Use `resolver` adapters to connect the schema to the form library
- Keep form state local; only lift to server state after successful submission

```typescript
const schema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters'),
  website: z.string().url().optional(),
});

const form = useForm<z.infer<typeof schema>>({
  resolver: zodResolver(schema),
});
```

---

## Schema Sharing Across Layers

Derive frontend validation schemas from the same source as backend DTOs.

- Publish shared validation schemas as a package consumed by both frontend and backend
- Alternatively, generate frontend types from the OpenAPI spec (e.g. `openapi-typescript`)
- Eliminates drift between what the form accepts and what the API validates
- Breaking API changes surface as TypeScript errors at compile time

---

## Accessible Interactive Components

Build components that work for all users, not just mouse users.

- **Modals**: trap focus within the dialog; restore focus to the trigger on close; close on Escape
- **Async state**: use `aria-live="polite"` regions for status messages; avoid silent failures
- **Submit buttons**: set `aria-busy="true"` and `disabled` during submission to prevent double-submit
- **Form errors**: associate error messages with fields via `aria-describedby`
- **Keyboard nav**: test all interactive flows using keyboard-only navigation

```tsx
<button
  type="submit"
  aria-busy={isSubmitting}
  disabled={isSubmitting}
>
  {isSubmitting ? 'Creating...' : 'Create Organisation'}
</button>

<p id="name-error" role="alert">
  {errors.name?.message}
</p>
<input aria-describedby="name-error" {...register('name')} />
```

---

## References

- [TanStack Query (React Query)](https://tanstack.com/query)
- [react-hook-form](https://react-hook-form.com)
- [Zod](https://zod.dev)
- [openapi-typescript](https://openapi-ts.dev)
- [ARIA Authoring Practices Guide](https://www.w3.org/WAI/ARIA/apg/)
