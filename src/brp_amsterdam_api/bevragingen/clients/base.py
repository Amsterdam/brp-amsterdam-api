import logging
import time

from oauthlib.oauth2 import InvalidClientError
from urllib.parse import urlparse

import requests
from more_ds.network import URL
from requests import Timeout, ConnectionError
from rest_framework.exceptions import APIException

from brp_amsterdam_api.bevragingen.exceptions import GatewayTimeout, ServiceUnavailable

logger = logging.getLogger(__name__)

USER_AGENT = "BRP-Amsterdam-API/1.0"


class BaseBrpClient:
    """
    Base BRP Client to consume BRP API's using a mtls connection
    """

    endpoint_url: URL

    def __init__(
        self,
        endpoint_url,
        *,
        cert_file=None,
        key_file=None,
    ):
        """Initialize the client configuration.

        :param endpoint_url: Full URL of the BRP service.
        :param cert_file: Optional certificate file for mTLS (needed in production).
        :param key_file: Optional private key file for mTLS (needed in production).
        """
        if not endpoint_url:
            raise ValueError("Missing BRP endpoint URL")
        self.endpoint_url = URL(endpoint_url)
        self._host = urlparse(endpoint_url).netloc

        self._session = requests.Session()

        if cert_file is not None:
            self._session.cert = (cert_file, key_file)

    def __repr__(self):
        return f"<{self.__class__.__qualname__}: {self.endpoint_url}>"

    def call(self, hc_request: dict | None = None) -> requests.Response | APIException:
        """Make an HTTP GET call. kwargs are passed to pool.request."""
        logger.debug("calling %s", self.endpoint_url)
        t0 = time.perf_counter_ns()
        try:
            self._prepare_request()

            # Using urllib directly instead of requests for performance
            response: requests.Response = self._session.request(
                "POST",
                self.endpoint_url,
                json=hc_request,
                timeout=60,
                headers={
                    # "Authorization": "Bearer <oauthtoken>" is inserted by requests-oauthlib
                    "Accept": "application/json; charset=utf-8",
                    "Content-Type": "application/json; charset=utf-8",
                    "User-Agent": USER_AGENT,
                },
            )
        except InvalidClientError as e:
            # OAuth client credentials are invalid.
            logger.error("Proxy call to %s failed, invalid OAuth client credentials: %s", host, e)
            raise ServiceUnavailable() from e
        except (TimeoutError, Timeout) as e:
            # Socket timeout
            logger.error("Proxy call to %s failed, timeout from remote server: %s", self._host, e)
            raise GatewayTimeout() from e
        except (OSError, ConnectionError) as e:
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
        # Raise exception in nicer format, but chain with the original one
        # so the "response" object is still accessible via __cause__.response.
        try:
            response.raise_for_status()
        except requests.HTTPError as e:
            raise self._get_http_error(response) from e

    def _get_http_error(self, response: requests.Response) -> APIException:
        raise NotImplementedError

    def _prepare_request(self):
        """
        This method can be overwritten to prepare a request per client.
        """
