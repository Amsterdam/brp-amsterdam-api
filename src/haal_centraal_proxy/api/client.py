"""Client for Haal Centraal API. """

import logging
import time
from urllib.parse import urlparse

import orjson
import requests
from more_ds.network.url import URL
from requests import Timeout
from rest_framework import status
from rest_framework.exceptions import APIException, NotFound

from .exceptions import BadGateway, GatewayTimeout, RemoteAPIException, ServiceUnavailable

logger = logging.getLogger(__name__)

USER_AGENT = "Amsterdam-Haal-Centraal-Proxy/1.0"


class HaalCentraalClient:
    """Haal Centraal API client.

    When a reference to the client is kept globally,
    its HTTP connection pool can be reused between threads.
    """

    endpoint_url: URL

    def __init__(self, endpoint_url, api_key, cert_file=None, key_file=None):
        """Initialize the client configuration.

        :param endpoint_url: Full URL of the Haal Centraal service
        :param api_key: The API key to use
        :param cert_file: Optional certificate file for mTLS (needed in production).
        :param key_file: Optional private key file for mTLS (needed in production).
        """
        if not endpoint_url:
            raise ValueError("Missing Haal Centraal base_url")
        self.endpoint_url = URL(endpoint_url)
        self._api_key = api_key
        self._host = urlparse(endpoint_url).netloc
        self._session = requests.Session()
        if cert_file is not None:
            self._session.cert = (cert_file, key_file)

    def call(self, hc_request: dict | None = None) -> requests.Response:
        """Make an HTTP GET call. kwargs are passed to pool.request."""
        logger.debug("calling %s", self.endpoint_url)
        t0 = time.perf_counter_ns()
        try:
            # Using urllib directly instead of requests for performance
            response: requests.Response = self._session.request(
                "POST",
                self.endpoint_url,
                json=hc_request,
                timeout=60,
                headers={
                    "Accept": "application/json; charset=utf-8",
                    "Content-Type": "application/json; charset=utf-8",
                    "X-API-Key": self._api_key,
                    "User-Agent": USER_AGENT,
                },
            )
        except (TimeoutError, Timeout) as e:
            # Socket timeout
            logger.error("Proxy call to %s failed, timeout from remote server: %s", self._host, e)
            raise GatewayTimeout() from e
        except OSError as e:
            # Socket connect / SSL error.
            logger.error(
                "Proxy call to %s failed, error when connecting to server: %s", self._host, e
            )
            raise ServiceUnavailable(str(e)) from e

        # Log response and timing results
        level = logging.ERROR if response.status_code >= 400 else logging.INFO
        logger.log(
            level,
            "Proxy call to %s, status %s: %s (%s), took: %.3fs",
            self.endpoint_url,
            response.status_code,
            response.reason,
            response.headers.get("content-type"),
            (time.perf_counter_ns() - t0) * 1e-9,
        )

        if 200 <= response.status_code < 300:
            return response

        # We got an error.
        if logger.isEnabledFor(logging.DEBUG):
            content_type = response.headers.get("content-type", "")
            if content_type and "json" in content_type and response.content.startswith(b'{"'):
                # For application/json and application/problem+json,
                logger.debug(
                    "  Decoded JSON response body",
                    extra={
                        "hc_request": hc_request,
                        "hc_response": orjson.loads(response.content),
                    },
                )
            else:
                logger.debug("  Response body: %s", response.text)

        # Raise exception in nicer format, but chain with the original one
        # so the "response" object is still accessible via __cause__.response.
        try:
            response.raise_for_status()
        except requests.HTTPError as e:
            raise self._get_http_error(response) from e

    def _get_http_error(self, response: requests.Response) -> APIException:
        # Translate the remote HTTP error to the proper response.
        #
        # This translates some errors into a 502 "Bad Gateway" or 503 "Gateway Timeout"
        # error to reflect the fact that this API is calling another service as backend.

        # Consider the actual JSON response here,
        # unless the request hit the completely wrong page (it got an HTML page).
        content_type = response.headers.get("content-type", "")
        remote_json = (
            orjson.loads(response.content)
            if content_type in ("application/json", "application/problem+json")
            else None
        )
        detail_message = response.text if not content_type.startswith("text/html") else None

        if not remote_json:
            # Unexpected response, call it a "Bad Gateway"
            logger.error(
                "Proxy call failed, unexpected status code from endpoint: %s %s",
                response.status_code,
                detail_message,
            )
            return BadGateway(
                detail_message or f"Unexpected HTTP {response.status_code} from internal endpoint"
            )

        if response.status_code == status.HTTP_401_UNAUTHORIZED or (
            response.status_code == status.HTTP_403_FORBIDDEN
            and remote_json is not None
            and remote_json["title"] == "U bent niet geautoriseerd voor het gebruik van deze API."
        ):
            # Our API key is not configured (401) or incorrect (403). Don't blame the client.
            # So far there is no other cause for a 403, but allow this to change.
            return BadGateway(
                "Backend is improperly configured, final endpoint rejected our credentials.",
                code="backend_config",
            )
        elif response.status_code in (status.HTTP_400_BAD_REQUEST, status.HTTP_403_FORBIDDEN):
            # Bad request likely means the JSON parameters were invalid.
            # Translate proper "Bad Request" to REST response
            return RemoteAPIException(response.status_code, remote_json)
        elif response.status_code == status.HTTP_404_NOT_FOUND:
            # Return 404 to client (in DRF format)
            if content_type == "application/problem+json":
                # Forward the problem-json details, but still in a 404:
                return RemoteAPIException(response.status_code, remote_json)
            return NotFound(repr(remote_json))
        else:
            # Unexpected response, call it a "Bad Gateway"
            logger.error(
                "Proxy call failed, unexpected status code from endpoint: %s %s",
                response.status,
                detail_message,
            )
            return BadGateway(
                detail_message or f"Unexpected HTTP {response.status} from internal endpoint"
            )
