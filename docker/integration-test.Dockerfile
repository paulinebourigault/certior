# Dockerfile for the Certior integration test suite.
#
# Contains: Python 3.13, certior (editable), openclaw-sdk, pytest.
# Used by .github/workflows/integration-test-ci.yml and locally via
# docker compose -f docker/integration-test.compose.yml run --rm integration.
#
# Isolates openclaw-sdk and any code it imports from the host. The
# container has no privileged access and no network egress beyond the
# install step.

FROM python:3.13-slim

# Non-root user - the test harness has no need for root and we want
# defense in depth in case openclaw-sdk's import path tries something
# unexpected at module-load time.
RUN useradd --create-home --shell /bin/bash runner

# Install certior in editable mode + openclaw-sdk + pytest.
# We do this as root before switching users so /home/runner/.cache
# does not get polluted with root-owned wheels.
WORKDIR /work
COPY pyproject.toml README.md README-PYPI.md LICENSE MANIFEST.in CHANGELOG.md SECURITY.md ./
COPY certior ./certior
COPY agentsafe ./agentsafe
COPY tests ./tests

RUN pip install --no-cache-dir -e ".[openclaw]" \
                                 pytest>=8.0 \
                                 pytest-asyncio>=0.23 \
 && chown -R runner:runner /work

USER runner

# Default to the integration test set - the live one in particular -
# but allow overriding by passing alternative pytest args:
#   docker run --rm integration tests/  # full suite
CMD ["python", "-m", "pytest", "-v", "tests/test_adapters/test_openclaw_live.py"]
