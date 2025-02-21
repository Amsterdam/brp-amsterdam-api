import logging
from copy import deepcopy

import orjson
import requests
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse
from django.urls import reverse
from rest_framework import status
from rest_framework.exceptions import APIException
from rest_framework.request import Request
from rest_framework.views import APIView

from haal_centraal_proxy.api import authentication, permissions
from haal_centraal_proxy.api.client import HaalCentraalClient
from haal_centraal_proxy.api.exceptions import ProblemJsonException
from haal_centraal_proxy.api.permissions import ParameterPolicy

logger = logging.getLogger(__name__)
audit_log = logging.getLogger("haal_centraal_proxy.audit")


class BaseProxyView(APIView):
    """View that proxies Haal Centraal BRP.

    This is a pass-through proxy, but with authorization and extra restrictions added.
    The subclasses implement the variations between Haal Centraal endpoints.
    """

    #: Define which additional scopes are needed
    client_class = HaalCentraalClient

    authentication_classes = [authentication.JWTAuthentication]

    # Need to define for every subclass:

    #: An random short-name for the service name in logging statements
    service_log_id: str = None
    #: Which endpoint to proxy
    endpoint_url: str = None
    #: The based scopes needed for all requests.
    needed_scopes: set = None
    #: The ruleset which parameters are allowed, or require additional roles.
    parameter_ruleset: dict[str, ParameterPolicy] = None

    def setup(self, request, *args, **kwargs):
        """Configure the view before the request handling starts.
        This is the main Django view setup.
        """
        super().setup(request, *args, **kwargs)
        self._base_url = reverse(request.resolver_match.view_name)
        self.client = self.get_client()

    def get_client(self) -> HaalCentraalClient:
        """Provide the Haal Centraal client. This can be overwritten per view if needed."""
        return self.client_class(
            endpoint_url=self.endpoint_url,
            api_key=settings.HAAL_CENTRAAL_API_KEY,
            cert_file=settings.HAAL_CENTRAAL_CERT_FILE,
            key_file=settings.HAAL_CENTRAAL_KEY_FILE,
        )

    def get_permissions(self):
        """Collect the DRF permission checks.
        DRF checks these in the initial() method, and will block view access
        if these permissions are not satisfied.
        """
        if not self.needed_scopes:
            raise ImproperlyConfigured("needed_scopes is not set")

        return super().get_permissions() + [permissions.IsUserScope(self.needed_scopes)]

    def get_parameter_ruleset(self, hc_request: dict) -> dict[str, ParameterPolicy]:
        """Allow overriding which parameter ruleset to use."""
        return self.parameter_ruleset

    def post(self, request: Request, *args, **kwargs):
        """Handle the incoming POST request.
        Basic checks (such as content-type validation) are already done by REST Framework.
        The API uses POST so the logs won't include personally identifiable information (PII).
        """
        # Parse the request
        self.user_scopes = set(request.get_token_scopes)
        self.user_id = request.get_token_claims.get("email", request.get_token_subject)
        hc_request = request.data.copy()

        # Perform validation
        try:
            needed_param_scopes = permissions.validate_parameters(
                self.get_parameter_ruleset(hc_request), hc_request, self.user_scopes
            )
        except permissions.AccessDenied as err:
            # Logging happens at the view level, to have full context.
            self.log_access_denied(hc_request, err)

            # Return error response
            denied_values = ", ".join(err.denied_values)
            raise ProblemJsonException(
                title="U bent niet geautoriseerd voor deze operatie.",
                detail=f"U bent niet geautoriseerd voor {err.field_name} = {denied_values}.",
                code="permissionDenied",  # Same as what Haal Centraal would do.
                status=status.HTTP_403_FORBIDDEN,
                invalid_params=[
                    {"name": err.field_name, "code": "denied", "reason": "Geen toegang."}
                ],
            ) from err

        # Allow inserting missing parameters, etc...
        self.transform_request(hc_request)

        # Proxy to Haal Centraal
        try:
            downstream_response = self.client.call(hc_request)
        except (APIException, OSError) as e:
            # Even when the request failed, still log that we did grant access.
            hc_response = (
                e.__cause__.response.json()
                if isinstance(e.__cause__, requests.RequestException)
                else None
            )

            self.log_access_granted(
                request,
                hc_request,
                hc_response,
                final_response=None,
                needed_scopes=self.needed_scopes | needed_param_scopes,
                exception=e,
            )
            raise

        # Rewrite the response to pagination still works.
        # (currently in in-place)
        hc_response = orjson.loads(downstream_response.text)
        final_response = deepcopy(hc_response)
        self.transform_response(hc_request, final_response)

        # Post it to audit logging, both when everything went ok, or failed.
        self.log_access_granted(
            request,
            hc_request,
            hc_response,
            final_response,
            needed_scopes=self.needed_scopes | needed_param_scopes,
        )

        # And return it.
        return HttpResponse(
            orjson.dumps(final_response),
            content_type=downstream_response.headers.get(
                "content-type", "application/json; charset=utf-8"
            ),
        )

    def log_access_denied(self, hc_request: dict, err: permissions.AccessDenied) -> None:
        """Perform the audit logging for the denied request."""
        missing = sorted(err.needed_scopes - self.user_scopes)
        audit_log.info(
            "Denied access to '%(service)s.%(query_type)s'"
            " for %(field)s=%(values)s, missing %(missing)s",
            {
                "service": self.service_log_id,
                "query_type": hc_request["type"],
                "field": err.field_name,
                "values": ",".join(err.denied_values),
                "missing": ",".join(missing),
            },
            extra={
                "service": self.service_log_id,
                "query_type": hc_request["type"],
                "field": err.field_name,
                "values": err.denied_values,
                "granted": sorted(self.user_scopes),
                "needed": sorted(err.needed_scopes),
                "missing": missing,
            },
        )

    def log_access_granted(
        self,
        request,
        hc_request: dict,
        hc_response: dict | None,
        final_response: dict | None,
        needed_scopes: set[str],
        exception: OSError | APIException | None = None,
    ) -> None:
        """Perform the audit logging for the request/response.

        This is a very basic global logging.
        Per service type, it may need more refinement.
        """
        extra = {
            "service": self.service_log_id,
            "query_type": hc_request["type"],
            "user": self.user_id,
            "granted": sorted(self.user_scopes),
            "needed": sorted(needed_scopes),
            "request": request.data,
            "hc_request": hc_request,
            "hc_response": final_response or hc_response,
        }

        if exception is None:
            msg = (
                "Access granted for '%(service)s.%(query_type)s' to '%(user)s'"
                " (full request/response in detail)"
            )
        else:
            msg = (
                "Access granted for '%(service)s.%(query_type)s' to '%(user)s'"
                ", but error returned (full request/response in detail)"
            )
            extra["exception"] = str(exception)

        # user.AuthenticatedId is already added globally.
        # TODO:
        # - afnemerindicatie (client certificaat)
        # - session ID van afnemende applicatie.
        audit_log.info(
            msg,
            {
                "service": self.service_log_id,
                "query_type": hc_request["type"],
                "user": self.user_id,
            },
            extra=extra,
        )

    def transform_request(self, hc_request: dict) -> None:
        """This method can be overwritten to provide extra request parameter handling per endpoint.
        It may perform in-place replacements of the request.
        """

    def transform_response(self, hc_request: dict, hc_response: dict | list) -> None:
        """Replace hrefs in _links sections by whatever fn returns for them.

        May modify data in-place.
        """
        self._rewrite_links(
            hc_response,
            rewrites=[
                (self.client.endpoint_url, self._base_url),
            ],
        )

    def _rewrite_links(
        self, data: dict | list, rewrites: list[tuple[str, str]], in_links: bool = False
    ):
        if isinstance(data, list):
            # Lists: go level deeper
            for child in data:
                self._rewrite_links(child, rewrites, in_links)
        elif isinstance(data, dict):
            # First or second level: dict
            if in_links and isinstance(href := data.get("href"), str):
                for find, replace in rewrites:
                    if href.startswith(find):
                        data["href"] = f"{replace}{href[len(find):]}"
                        break

            if links := data.get("_links"):
                # Go level deeper, can skip other keys
                self._rewrite_links(links, rewrites, in_links=True)
            else:
                # Dict: go level deeper
                for child in data.values():
                    self._rewrite_links(child, rewrites, in_links)
