# Database Query Skill

## Description
Execute read-only SQL queries with column-level access control, row limits,
and information flow tracking. Sensitive columns (passwords, SSNs, credit cards)
are automatically blocked.

## Capabilities Required
- `database:read` - Execute SELECT queries

## Safety Guarantees
- **Read-only**: Only SELECT statements; no INSERT/UPDATE/DELETE
- **Forbidden columns**: `password`, `ssn`, `credit_card` columns blocked
- **Row limits**: Maximum 10,000 rows per query
- **Timeout**: 30-second query timeout
- **Table restrictions**: Only `public.*` tables accessible by default

## Formal Properties (Z3-verified)
1. `no_forbidden_columns` - `selected_columns(query) ∩ forbidden_columns = ∅`
2. `row_limit_enforced` - All queries include LIMIT ≤ max_rows
3. `read_only` - No mutation statements permitted

## Compliance
- **HIPAA**: Applicable - may access patient data
- **SOX**: Applicable - may access financial records
- **GDPR**: Applicable - may query personal data

## Usage
```python
skill = loader.load_skill("database_query", token)
engine = skill.implementation.SafeDatabaseQuery(skill.verification)
rows = await engine.execute("SELECT name, email FROM users LIMIT 100")
```
