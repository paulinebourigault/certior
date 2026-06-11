"""Tests for webhook delivery."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from agentsafe.cloud.webhook import WebhookManager, WebhookDelivery


def _mock_httpx_success(status_code=200):
    """Create a mock that makes httpx.AsyncClient return a success response."""
    mock_resp = MagicMock(status_code=status_code)
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_resp)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    return patch("httpx.AsyncClient", return_value=mock_client), mock_client


class TestWebhookManager:
    @pytest.mark.asyncio
    async def test_deliver_success(self):
        wh = WebhookManager()
        patcher, mock_client = _mock_httpx_success()
        with patcher:
            delivery = await wh.deliver(
                "https://example.com/hook",
                {"status": "complete"},
            )
        assert delivery.status == "delivered"
        assert delivery.last_status_code == 200
        assert delivery.attempts == 1
        assert len(wh.delivered) == 1
        mock_client.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_deliver_retry_on_failure(self):
        """Retries up to max_attempts on non-2xx responses."""
        wh = WebhookManager(max_attempts=2)
        patcher, mock_client = _mock_httpx_success(500)
        with patcher:
            delivery = await wh.deliver("https://example.com/hook", {"a": 1})
        assert delivery.status == "failed"
        assert delivery.attempts == 2
        assert len(wh.failed) == 1

    @pytest.mark.asyncio
    async def test_deliver_success_on_second_try(self):
        """Succeeds on retry after initial failure."""
        wh = WebhookManager(max_attempts=3)
        fail_resp = MagicMock(status_code=502)
        ok_resp = MagicMock(status_code=200)
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=[fail_resp, ok_resp])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        with patch("httpx.AsyncClient", return_value=mock_client):
            delivery = await wh.deliver("https://example.com/hook", {"a": 1})
        assert delivery.status == "delivered"
        assert delivery.attempts == 2

    def test_sign_and_verify(self):
        wh = WebhookManager("secret-key")
        payload = {"data": "test"}
        sig = wh.sign_payload(payload)
        assert wh.verify_signature(payload, sig)
        assert not wh.verify_signature(payload, "wrong-sig")

    def test_sign_deterministic(self):
        wh = WebhookManager("key")
        sig1 = wh.sign_payload({"a": 1, "b": 2})
        sig2 = wh.sign_payload({"b": 2, "a": 1})
        assert sig1 == sig2  # sort_keys=True

    @pytest.mark.asyncio
    async def test_multiple_deliveries(self):
        wh = WebhookManager()
        patcher, _ = _mock_httpx_success()
        with patcher:
            await wh.deliver("url1", {"a": 1})
            await wh.deliver("url2", {"b": 2})
        assert len(wh.delivered) == 2

    @pytest.mark.asyncio
    async def test_delivery_records_metadata(self):
        wh = WebhookManager()
        patcher, _ = _mock_httpx_success()
        with patcher:
            delivery = await wh.deliver("https://example.com", {"x": 1})
        d = delivery.to_dict()
        assert "id" in d
        assert d["url"] == "https://example.com"
        assert d["status"] == "delivered"
        assert d["delivered_at"] is not None

    @pytest.mark.asyncio
    async def test_headers_include_signature(self):
        """Verify the POST includes HMAC signature header."""
        wh = WebhookManager("test-secret")
        patcher, mock_client = _mock_httpx_success()
        with patcher:
            await wh.deliver("https://example.com/hook", {"key": "val"})

        call_kwargs = mock_client.post.call_args
        headers = call_kwargs.kwargs.get("headers", {})
        assert "X-Certior-Signature" in headers
        assert "X-Certior-Delivery" in headers
