from rest_framework.authentication import BaseAuthentication
from rest_framework.request import Request


class JWTAuthentication(BaseAuthentication):
    """Bridge the JWT authentication from authorization-django to DRF views."""

    www_authenticate_realm = "brp-bevragingen-api"

    def authenticate(self, request):
        """Tell REST Framework that we do have an authentication header.
        This makes sure an HTTP 403 (Forbidden) response is given instead of 401 (Unauthorized).
        """
        if not request.get_token_claims:
            return None  # not authenticated

        # Is authenticated, fill "request.auth" and "request.authenticators".
        return None, request.get_token_claims

    def authenticate_header(self, request: Request) -> str:
        return f'Bearer realm="{self.www_authenticate_realm}"'
