"""Additional exception classes"""

from rest_framework import status
from rest_framework.exceptions import APIException


class BadGateway(APIException):
    """Render an HTTP 502 Bad Gateway."""

    status_code = status.HTTP_502_BAD_GATEWAY
    default_detail = "Connection failed (bad gateway)"
    default_code = "bad_gateway"


class ServiceUnavailable(APIException):
    """Render an HTTP 503 Service Unavailable."""

    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = "Connection failed (network trouble)"
    default_code = "service_unavailable"


class GatewayTimeout(APIException):
    """Render an HTTP 504 Gateway Timeout."""

    status_code = status.HTTP_504_GATEWAY_TIMEOUT
    default_detail = "Connection failed (server timeout)"
    default_code = "gateway_timeout"


class ProblemJsonException(APIException):
    """API exception that dictates exactly
    how the application/problem+json response looks like.
    """

    status_code = status.HTTP_400_BAD_REQUEST

    def __init__(
        self, title, detail, code, status=status.HTTP_400_BAD_REQUEST, invalid_params=None
    ):
        super().__init__(detail, code)
        self.code = code or self.default_code
        self.title = title
        self.status_code = status
        self.invalid_params = invalid_params


class RemoteAPIException(ProblemJsonException):
    """Indicate that a call to a remote endpoint failed."""
