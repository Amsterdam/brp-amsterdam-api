from unittest.mock import Mock

import pytest
from requests import Timeout

from brp_amsterdam_api.bevragingen.clients.rvig import (
    RvIGBrpClient,
)
from brp_amsterdam_api.bevragingen.exceptions import GatewayTimeout, ServiceUnavailable


class TestRvIGBrpClient:
    def test_fetch_token_retries_once_after_500ms_timeout(self, settings):
        settings.BACKEND_API = "rvig"
        client = RvIGBrpClient(
            endpoint_url="https://example.org/lap/api/brp/personen",
            oauth_endpoint_url="https://example.org/oauth/token",
            oauth_client_id="client-id",
            oauth_client_secret="secret",
        )

        token = {
            "token_type": "bearer",
            "access_token": "abc",
            "expires_in": 3600,
            "scope": "scope",
        }

        client._session.fetch_token = Mock(side_effect=[Timeout("timed out"), token])

        result = client.fetch_token()

        assert result == token
        assert client._session.fetch_token.call_count == 2

    def test_fetch_token_raises_gateway_timeout_after_retries(self, settings):
        settings.BACKEND_API = "rvig"
        client = RvIGBrpClient(
            endpoint_url="https://example.org/lap/api/brp/personen",
            oauth_endpoint_url="https://example.org/oauth/token",
            oauth_client_id="client-id",
            oauth_client_secret="secret",
        )

        client._session.fetch_token = Mock(side_effect=Timeout("timed out"))

        with pytest.raises(GatewayTimeout):
            client.fetch_token()

        client._session.fetch_token.assert_called()
        assert client._session.fetch_token.call_count == 2

    def test_fetch_token_raises_service_unavailable_if_no_token_returned(self, settings):
        settings.BACKEND_API = "rvig"
        client = RvIGBrpClient(
            endpoint_url="https://example.org/lap/api/brp/personen",
            oauth_endpoint_url="https://example.org/oauth/token",
            oauth_client_id="client-id",
            oauth_client_secret="secret",
        )

        client._session.fetch_token = Mock(return_value=None)

        with pytest.raises(ServiceUnavailable):
            client.fetch_token()

        client._session.fetch_token.assert_called()
