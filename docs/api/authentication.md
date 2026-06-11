---
title: "Authentication"
description: "Register a user, log in, rotate an API key, read the current user. API keys go in the Authorization header."
---

Authentication lives under `/api/v1/auth/`. Every endpoint outside `/auth/register` and `/auth/login` requires `Authorization: Bearer <api-key>`.

The route file is [`app/api/routes/auth.py`](https://github.com/paulinebourigault/certior/blob/main/app/api/routes/auth.py).

## `POST /auth/register`

Create a new user account and receive an API key.

**Request body** (`RegisterRequest`):

```json
{
  "email":    "demo@example.com",
  "name":     "Demo User",
  "password": "..."
}
```

**Response** (`201 Created`, `RegisterResponse`):

```json
{
  "user_id":  "...",
  "email":    "demo@example.com",
  "api_key":  "ck_..."
}
```

The `api_key` is shown once. Store it securely.

## `POST /auth/login`

Exchange credentials for an API key.

**Request body** (`LoginRequest`):

```json
{ "email": "demo@example.com", "password": "..." }
```

**Response** (`LoginResponse`): same shape as register.

## `POST /auth/rotate`

Rotate the calling user's API key. Old key is invalidated; new one is returned.

```http
POST /api/v1/auth/rotate
Authorization: Bearer <current-api-key>
```

**Response** (`RotateKeyResponse`):

```json
{ "api_key": "ck_new..." }
```

## `GET /auth/me`

Return the current user.

```http
GET /api/v1/auth/me
Authorization: Bearer <api-key>
```

**Response** (`UserResponse`):

```json
{
  "user_id": "...",
  "email":   "demo@example.com",
  "name":    "Demo User",
  "roles":   ["VIEWER"]
}
```

## Roles

The codebase recognises `ADMIN`, `OPERATOR`, `APPROVER`, `AUDITOR`, `VIEWER`, and `POLICY_AUTHOR`. Endpoints that require a specific role declare it via the `require_role(...)` dependency - see the per-endpoint docs.

## `DELETE /auth/users/{user_id}`

Admin-only. Deletes a user. Requires the calling user's role to include `ADMIN`.

## See also

- [Tasks](/api/tasks) - first endpoint that needs an API key.
- [Configuration](/reference/configuration) - the env vars that control key storage.
