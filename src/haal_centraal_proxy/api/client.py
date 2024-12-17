"""Client for Haal Centraal API.

Endpoints are queried with raw *urllib3*,
to avoid the overhead of the *requests* library.
"""

import logging
import time
from dataclasses import dataclass
from urllib.parse import urlparse

import certifi
import orjson
import urllib3
from more_ds.network.url import URL
from rest_framework import status
from rest_framework.exceptions import APIException, NotFound, ParseError, PermissionDenied
from urllib3 import BaseHTTPResponse

from .exceptions import BadGateway, GatewayTimeout, RemoteAPIException, ServiceUnavailable

logger = logging.getLogger(__name__)

USER_AGENT = "Amsterdam-Haal-Centraal-Proxy/1.0"


@dataclass(frozen=True)
class HaalCentraalResponse:
    """The response from the remote system"""

    headers: dict
    data: list | dict


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
        self._pool = urllib3.PoolManager(
            cert_reqs="CERT_REQUIRED",
            cert_file=cert_file,
            key_file=key_file,
            ca_certs=certifi.where(),
        )

    def call(self, hc_request: dict | None = None) -> HaalCentraalResponse:
        """Make an HTTP GET call. kwargs are passed to pool.request."""
        logger.debug("calling %s", self.endpoint_url)
        t0 = time.perf_counter_ns()
        try:
            # Using urllib directly instead of requests for performance
            response: BaseHTTPResponse = self._pool.request(
                "POST",
                self.endpoint_url,
                body=orjson.dumps(hc_request),
                timeout=60,
                retries=False,
                headers={
                    "Accept": "application/json; charset=utf-8",
                    "Content-Type": "application/json; charset=utf-8",
                    "X-API-Key": self._api_key,
                    "User-Agent": USER_AGENT,
                },
            )
        except (TimeoutError, urllib3.exceptions.TimeoutError) as e:
            # Socket timeout
            logger.error("Proxy call to %s failed, timeout from remote server: %s", self._host, e)
            raise GatewayTimeout() from e
        except (OSError, urllib3.exceptions.HTTPError) as e:
            # Socket connect / SSL error (HTTPError is the remote class for errors)
            logger.error(
                "Proxy call to %s failed, error when connecting to server: %s", self._host, e
            )
            raise ServiceUnavailable(str(e)) from e

        # Log response and timing results
        level = logging.ERROR if response.status >= 400 else logging.INFO
        logger.log(
            level,
            "Proxy call to %s, status %s: %s (%s), took: %.3fs",
            self._host,
            response.status,
            response.reason,
            response.headers.get("content-type"),
            (time.perf_counter_ns() - t0) * 1e-9,
        )

        if 200 <= response.status < 300:
            return HaalCentraalResponse(
                headers=response.headers,
                data=orjson.loads(response.data),
            )

        # We got an error.
        if logger.isEnabledFor(logging.DEBUG):
            if "json" in response.headers["content-type"] and response.data.startswith(b'{"'):
                # For application/json and application/problem+json,
                logger.debug(
                    "  Decoded JSON response body",
                    extra={
                        "hc_request": hc_request,
                        "hc_response": orjson.loads(response.data),
                    },
                )
            else:
                logger.debug("  Response body: %s", response.data)

        raise self._get_http_error(response)

    def _get_http_error(self, response: BaseHTTPResponse) -> APIException:
        # Translate the remote HTTP error to the proper response.
        #
        # This translates some errors into a 502 "Bad Gateway" or 503 "Gateway Timeout"
        # error to reflect the fact that this API is calling another service as backend.

        # Consider the actual JSON response here,
        # unless the request hit the completely wrong page (it got an HTML page).
        content_type = response.headers.get("content-type", "")
        detail_message = (
            response.data.decode() if not content_type.startswith("text/html") else None
        )
        remote_json = (
            orjson.loads(response.data)
            if content_type in ("application/json", "application/problem+json")
            else None
        )

        if response.status == status.HTTP_400_BAD_REQUEST:
            if remote_json is not None:
                # Translate proper "Bad Request" to REST response
                return RemoteAPIException(
                    title=remote_json.get("title", ParseError.default_detail),
                    detail=remote_json.get("detail"),
                    code=remote_json.get("code", ParseError.default_code),
                    status=400,
                    invalid_params=remote_json.get("invalidParams"),
                )
            else:
                return BadGateway(detail_message)
        elif response.status in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN):
            # We translate 401 to 403 because 401 MUST have a WWW-Authenticate header in the
            # response, and we can't easily set that from here. Also, RFC 7235 says we MUST NOT
            # change such a header, which presumably includes making one up.
            remote_detail = (
                remote_json.get("title", "") if remote_json is not None else repr(response.data)
            )
            return RemoteAPIException(
                title=PermissionDenied.default_detail,
                detail=f"{response.status} from remote: {remote_detail}",
                status=status.HTTP_403_FORBIDDEN,
                code=remote_json.get("code", PermissionDenied.default_code),
            )
        elif response.status == status.HTTP_404_NOT_FOUND:
            # Return 404 to client (in DRF format)
            if content_type == "application/problem+json":
                # Forward the problem-json details, but still in a 404:
                return RemoteAPIException(
                    title=remote_json.get("title", NotFound.default_detail),
                    detail=remote_json.get("detail"),
                    status=404,
                    code=remote_json.get("code", NotFound.default_code),
                )
            return NotFound(detail_message)
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
