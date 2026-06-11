# Certior API Contract and Compatibility Guarantees

## Versioning Model
Certior APIs are versioned in the URL path (e.g., `/api/v1/...`). 

### Compatibility Guarantees
For any `v1` endpoint (such as `/api/v1/releases/decision`):
- **Response Shape Stability**: We will not remove fields, change their types, or make existing optional fields mandatory.
- **Additive Changes**: We may add new fields to response payloads in minor versions. SDK clients and API consumers must ignore unknown fields.
- **Enum Stability**: Existing enum values (e.g., `"SHIP" | "NO_SHIP"`) will not change their string representation or underlying meaning. Additional values will be clearly documented and only introduced if backwards-compatible fallback exists.

### Deprecation Rules
If a breaking change is unavoidable, the deprecation policy is:
1. Introduce a new API version (e.g., `v2`).
2. Mark the `v1` endpoint as `[Deprecated]` in OpenAPI docs.
3. Provide a minimum of a **6-month migration window** where `v1` continues to function exactly as before.
4. Publish explicit migration notes detailing how to transition.

## Key Payload Definitions

### Release Decision (`/api/v1/releases/decision`)
Exposes the canonical decision of release readiness. Designed for external CI/CD platforms as a deployment gate.

**Response Schema Highlights**:
- `decision` (`"SHIP"` | `"NO_SHIP"`): Overall determination. Any external gate should only deploy if this equals `"SHIP"`.
- `blockers`: List of distinct blocking violations (why a release is `"NO_SHIP"`).
- `baseline`: Context comparing against the last successful `"attested"` snapshot.
