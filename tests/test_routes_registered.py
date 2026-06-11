"""
test_routes_registered.py
=========================

Pins a load-bearing invariant: every router declared in
``app/api/routes/`` must be mounted by ``app.main.create_app()``. If
you add a new file under ``app/api/routes/`` that declares a
``router = APIRouter(...)`` and forget the matching
``app.include_router(...)`` line in ``create_app()``, this test
fails.

This is the same class of bug that hid the
``/api/v1/releases/*``, ``/api/v1/trust/badge``, and
``/api/v1/agents/*`` namespaces for months: the route files existed
in source, the OpenAPI schema listed them, every external call hit a
``404``. The check is cheap (~ms) so we run it on every commit.
"""
from __future__ import annotations

import importlib
import pkgutil
from typing import Set

import pytest
from fastapi import APIRouter

from app.main import create_app
import app.api.routes as _routes_pkg


def _router_paths(router: APIRouter) -> Set[str]:
    """Paths a router contributes to the app after ``include_router``.

    In the FastAPI version this project pins, the ``prefix`` is baked
    into each ``route.path`` at decoration time - ``router.routes`` is
    already fully prefixed. So we just collect ``route.path`` verbatim.
    """
    return {
        getattr(route, "path", "")
        for route in router.routes
        if hasattr(route, "path")
    }


def _route_modules_with_routers() -> dict[str, APIRouter]:
    """Return ``{module_name: router}`` for every routes/*.py with a router."""
    out: dict[str, APIRouter] = {}
    for _, module_name, _ in pkgutil.iter_modules(_routes_pkg.__path__):
        module = importlib.import_module(f"app.api.routes.{module_name}")
        router = getattr(module, "router", None)
        if isinstance(router, APIRouter):
            out[module_name] = router
    return out


def test_every_route_module_is_mounted_by_create_app() -> None:
    """Catch routers that were defined but never wired into ``create_app``."""
    app = create_app()
    app_paths = {
        getattr(route, "path", "") for route in app.routes if hasattr(route, "path")
    }

    unmounted: list[str] = []
    for module_name, router in _route_modules_with_routers().items():
        expected = _router_paths(router)
        if not expected:
            # Router with no routes - nothing to assert.
            continue
        missing = expected - app_paths
        if missing:
            unmounted.append(
                f"app/api/routes/{module_name}.py declares a router "
                f"(prefix={router.prefix!r}) whose paths are absent from "
                f"create_app(): missing={sorted(missing)}. "
                f"Fix: add `app.include_router({module_name}.router)` "
                f"in app/main.py."
            )

    assert not unmounted, "\n  • " + "\n  • ".join(unmounted)


def test_create_app_mounts_the_critical_v1_namespaces() -> None:
    """Explicit guard for the three namespaces that were silently 404 before.

    Complements the generic test above with a hard-coded smoke check so
    a future refactor cannot accidentally weaken the coverage.
    """
    app = create_app()
    app_paths = {
        getattr(route, "path", "") for route in app.routes if hasattr(route, "path")
    }

    required = {
        "/api/v1/releases/decision",
        "/api/v1/releases/health",
        "/api/v1/trust/badge",
        "/api/v1/agents/delegation-graph",
        "/api/v1/agents/glass-box-records",
    }

    missing = required - app_paths
    assert not missing, f"critical routes not mounted: {sorted(missing)}"
