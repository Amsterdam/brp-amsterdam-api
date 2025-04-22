"""Additional exception classes"""

from rest_framework import exceptions, status

CLASS_BY_CODE = {e.status_code: e for e in (exceptions.ParseError, exceptions.NotFound)}


class BadGateway(exceptions.APIException):
    """Render an HTTP 502 Bad Gateway."""

    status_code = status.HTTP_502_BAD_GATEWAY
    default_detail = "Connection failed (bad gateway)"
    default_code = "bad_gateway"


class ServiceUnavailable(exceptions.APIException):
    """Render an HTTP 503 Service Unavailable."""

    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = "Connection failed (network trouble)"
    default_code = "service_unavailable"


class GatewayTimeout(exceptions.APIException):
    """Render an HTTP 504 Gateway Timeout."""

    status_code = status.HTTP_504_GATEWAY_TIMEOUT
    default_detail = "Connection failed (server timeout)"
    default_code = "gateway_timeout"


class ProblemJsonException(exceptions.APIException):
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

    def __init__(self, status: int, remote_json: dict):
        default = CLASS_BY_CODE[status]
        super().__init__(
            title=remote_json.get("title", default.default_detail),
            detail=remote_json.get("detail"),
            code=remote_json.get("code", default.default_code),
            status=status,
            invalid_params=remote_json.get("invalidParams"),
        )
        self.remote_json = remote_json
