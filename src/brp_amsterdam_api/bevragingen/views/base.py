import logging
import time
from collections.abc import Callable, Iterable
from copy import deepcopy

import orjson
import requests
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.utils.timezone import now
from django.views.decorators.cache import never_cache
from rest_framework import status
from rest_framework.exceptions import APIException, PermissionDenied
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle, ScopedRateThrottle
from rest_framework.views import APIView

from brp_amsterdam_api.bevragingen import authentication, encryption, permissions, types
from brp_amsterdam_api.bevragingen.client import BrpClient
from brp_amsterdam_api.bevragingen.exceptions import ProblemJsonException, RemoteAPIException
from brp_amsterdam_api.bevragingen.permissions import ParameterPolicy

logger = logging.getLogger(__name__)
audit_log = logging.getLogger("brp_amsterdam_api.audit")

DictOfDicts = dict[str, dict[str, dict]]

SCOPE_ENCRYPT_BSN = "benk-brp-encrypt-bsn"


class ClientMixin(APIView):

    #: Define which additional scopes are needed
    client_class = BrpClient

    #: Define the URL for the endpoint
    endpoint_url: str

    def get_client(self) -> BrpClient:
        """Provide the API client class. This can be overwritten per view if needed."""
        return self.client_class(
            endpoint_url=self.endpoint_url,
            oauth_endpoint_url=settings.BRP_OAUTH_TOKEN_URL,
            oauth_client_id=settings.BRP_OAUTH_CLIENT_ID,
            oauth_client_secret=settings.BRP_OAUTH_CLIENT_SECRET,
            oauth_scope=settings.BRP_OAUTH_SCOPE,
            cert_file=settings.BRP_MTLS_CERT_FILE,
            key_file=settings.BRP_MTLS_KEY_FILE,
        )


class BaseHealthCheckView(ClientMixin, APIView):
    """View that performs a dummy call to the BRP API for healthchecks."""

    authentication_classes = [authentication.JWTAuthentication]
    throttle_classes = [AnonRateThrottle, ScopedRateThrottle]

    dummy_request = {"type": "healthcheck"}

    def get(self, request, *args, **kwargs):
        try:
            client = self.get_client()
            hc_response = client.call(self.dummy_request)
        except RemoteAPIException as e:
            success = e.detail == "De foutieve parameter(s) zijn: type."
            return Response({"success": success, "response": e.remote_json})
        except (APIException, OSError) as e:
            return Response({"success": False, "exception": str(e)})

        return Response({"success": True, "response": hc_response})


class BaseProxyView(ClientMixin, APIView):
    """View that proxies RvIG BRP API.

    This is a pass-through proxy, but with authorization and extra restrictions added.
    The subclasses implement the variations between RvIG BRP endpoints.
    """

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

    def initial(self, request: Request, *args, **kwargs):
        """DRF-level initialization for all request types."""
        self._base_url = reverse(request.resolver_match.view_name)
        self.client = self.get_client()
        self.start_time = time.perf_counter_ns()
        self.start_date = now()

        # Perform authorization, permission checks and throttles.
        super().initial(request, *args, **kwargs)

        # Token is validated, extract token scopes that are set by the middleware
        self.user_scopes = set(request.get_token_scopes)
        self.upn = request.get_token_claims.get("email", request.get_token_subject)
        self.appid = request.get_token_claims.get("appid")

        try:
            # request.data is only available in initial(), not in setup()
            self.default_log_fields = {
                "service": self.service_log_id,
                "queryType": request.data.get("type", None),
                "upn": self.upn,
                "user": self.request.headers["X-User"],
                "correlationId": self.request.headers["X-Correlation-ID"],
                "taskDescription": self.request.headers["X-Task-Description"],
                "granted": sorted(self.user_scopes),
            }
            if self.appid:
                self.default_log_fields["appid"] = self.appid
        except KeyError as e:
            raise PermissionDenied(
                f"A required header is missing: {e.args[0]}", code="missingHeaders"
            ) from None

    def get_permissions(self):
        """Collect the DRF permission checks.
        DRF checks these in the initial() method, and will block view access
        if these permissions are not satisfied.
        """
        if not self.needed_scopes:
            raise ImproperlyConfigured("needed_scopes is not set")

        return super().get_permissions() + [
            permissions.IsUserScope(self.needed_scopes),
            permissions.HasRequiredHeaders(),
        ]

    def get_parameter_ruleset(self, hc_request: types.BaseQuery) -> dict[str, ParameterPolicy]:
        """Allow overriding which parameter ruleset to use."""
        return self.parameter_ruleset

    @method_decorator(never_cache)
    def post(self, request: Request, *args, **kwargs):
        """Handle the incoming POST request.
        Basic checks (such as content-type validation) are already done by REST Framework.
        The API uses POST so the logs won't include personally identifiable information (PII).
        """
        hc_request = request.data.copy()

        # Decrypt certain values if needed by the user scope
        try:
            self.decrypt_request(hc_request)
        except encryption.DecryptionFailed as err:
            # Logging happens at the view level, to have full context.
            self.log_decryption_failed(hc_request, err)

            # Return error response
            raise ProblemJsonException(
                title="U bent niet geautoriseerd voor deze operatie.",
                detail=err.detail,
                code="permissionDenied",  # Same as what RvIG BRP API would do.
                status=status.HTTP_403_FORBIDDEN,
                invalid_params=[
                    {
                        "name": "burgerservicenummer",
                        "code": "denied",
                        "reason": "Geen toegang.",
                    }
                ],
            ) from err

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
                code="permissionDenied",  # Same as what RvIG BRP API would do.
                status=status.HTTP_403_FORBIDDEN,
                invalid_params=[
                    {"name": err.field_name, "code": "denied", "reason": "Geen toegang."}
                ],
            ) from err
        except permissions.InvalidParameters as err:
            # The parameter values are incorrect
            logger.info("Invalid parameter names: %s", err.invalid_names)
            raise ProblemJsonException(
                title="Een of meerdere parameters zijn niet correct.",
                detail=f"De foutieve parameter(s) zijn: {', '.join(err.invalid_names)}.",
                code="paramsValidation",
                status=status.HTTP_400_BAD_REQUEST,
            ) from err
        except permissions.InvalidValues as err:
            # The unsupported values
            logger.info("Invalid parameter values for %s: %s", err.field_name, err.invalid_values)
            raise ProblemJsonException(
                title="Een of meerdere veldnamen zijn niet correct.",
                detail=(
                    f"Het veld '{err.field_name}' ondersteunt niet"
                    f" de waarde(s): {', '.join(err.invalid_values)}."
                ),
                code="paramsValidation",
                status=status.HTTP_400_BAD_REQUEST,
            ) from err

        # Allow inserting missing parameters, etc...
        self.transform_request(hc_request)

        # Proxy to RvIG BRP API
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

        # Encrypt certain values if needed by the user scope
        self.encrypt_response(final_response)

        # And return it.
        return HttpResponse(
            orjson.dumps(final_response),
            content_type=downstream_response.headers.get(
                "content-type", "application/json; charset=utf-8"
            ),
        )

    def log_access_denied(
        self, hc_request: types.BaseQuery, err: permissions.AccessDenied
    ) -> None:
        """Perform the audit logging for the denied request."""
        missing = sorted(err.needed_scopes - self.user_scopes)
        audit_log.info(
            "Denied access to '%(service)s.%(queryType)s'"
            " for %(field)s=%(values)s, missing %(missing)s",
            {
                "service": self.service_log_id,
                "queryType": hc_request["type"],
                "field": err.field_name,
                "values": ",".join(err.denied_values),
                "missing": ",".join(missing),
            },
            extra={
                **self.default_log_fields,
                "field": err.field_name,
                "values": err.denied_values,
                "needed": sorted(err.needed_scopes),
                "missing": missing,
                "requestStarted": self.start_date,
                "requestProcessed": now(),
                "processingTime": (time.perf_counter_ns() - self.start_time) * 1e-9,
            },
        )

    def log_access_granted(
        self,
        request,
        hc_request: types.BaseQuery,
        hc_response: types.BaseResponse | None,
        final_response: types.BaseResponse | None,
        needed_scopes: set[str],
        exception: OSError | APIException | None = None,
    ) -> None:
        """Perform the audit logging for the request/response.

        This is a very basic global logging.
        Per service type, it may need more refinement.
        """
        extra = {
            **self.default_log_fields,
            "needed": sorted(needed_scopes),
            "request": request.data,
            "hcRequest": hc_request,
            "hcResponse": final_response or hc_response,
            "requestStarted": self.start_date,
            "requestProcessed": now(),
            "processingTime": (time.perf_counter_ns() - self.start_time) * 1e-9,
        }

        if exception is None:
            msg = (
                "Access granted for '%(service)s.%(queryType)s' to '%(upn)s'"
                " (full request/response in detail)"
            )
        else:
            msg = (
                "Access granted for '%(service)s.%(queryType)s' to '%(upn)s'"
                ", but error returned (full request/response in detail)"
            )
            extra["exception"] = str(exception)

        audit_log.info(
            msg,
            {
                "service": self.service_log_id,
                "queryType": hc_request["type"],
                "upn": self.upn,
            },
            extra=extra,
        )

    def log_decryption_failed(
        self, hc_request: types.BaseQuery, err: encryption.DecryptionFailed
    ) -> None:
        """Perform the audit logging for the denied request."""
        audit_log.info(
            "Denied access to '%(service)s.%(queryType)s'"
            " for unencrypted burgerservicenummer with scopes %(scopes)s",
            {
                "service": self.service_log_id,
                "queryType": hc_request["type"],
                "scopes": list(self.user_scopes),
            },
            extra={
                **self.default_log_fields,
                "field": "burgerservicenummer",
                "requestStarted": self.start_date,
                "requestProcessed": now(),
                "processingTime": (time.perf_counter_ns() - self.start_time) * 1e-9,
            },
        )

    def decrypt_request(self, hc_request: types.BaseQuery) -> None:
        """This method can be overwritten to provide extra request parameter handling per endpoint
        It may decrypt certain parts of the request for certain scopes in-place.
        """
        if SCOPE_ENCRYPT_BSN in self.user_scopes:
            self._process_bsn(hc_request, encryption.decrypt)

    def encrypt_response(self, hc_response: types.BaseResponse) -> None:
        """This method can be overwritten to provide extra request parameter handling per endpoint
        It may encrypt certain parts of the response for certain scopes in-place."""
        if SCOPE_ENCRYPT_BSN in self.user_scopes:
            self._process_bsn(hc_response, encryption.encrypt)

    def _process_bsn(self, item: list | dict, process_function: Callable) -> None:
        # We use the correlation id to salt the BSN
        correlation_id = self.request.headers["X-Correlation-ID"]

        if isinstance(item, list):
            for sub_item in item:
                self._process_bsn(sub_item, process_function)
        elif isinstance(item, dict):
            for key, value in item.items():
                # Encrypt all burgerservicenummers we encounter
                if key == "burgerservicenummer":
                    if isinstance(value, list):
                        item[key] = [process_function(v, salt=correlation_id) for v in value]
                        continue
                    item[key] = process_function(value, salt=correlation_id)

                if isinstance(value, (dict, list)):
                    self._process_bsn(value, process_function)

    def transform_request(self, hc_request: types.BaseQuery) -> None:
        """This method can be overwritten to provide extra request parameter handling per endpoint.
        It may perform in-place replacements of the request.
        """

    def transform_response(
        self, hc_request: types.BaseQuery, hc_response: types.BaseResponse | list
    ) -> None:
        """Replace hrefs in _links sections by whatever fn returns for them.

        May modify data in-place.
        """
        self._rewrite_links(
            hc_response,
            rewrites=[
                (self.client.endpoint_url, self._base_url),
            ],
        )

        # Restore sending null values for empty fields
        if self.request.GET.get("resultaat-formaat", None) == "volledig":
            self._insert_null_values(hc_request, hc_response)

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

    def _insert_null_values(
        self, hc_request: types.BaseQuery, hc_response: types.BaseResponse
    ) -> None:
        """This method can be overwritten to insert any null values that the user does have
        access to per endpoint. This allows the client to distinguish between having 'no value'
        instead of 'no access'.
        """

    def _include_nulls(self, request_fields: DictOfDicts, item: list | dict, parent_path=()):
        """Include null values based on the collection of requested fields"""
        if isinstance(item, list):
            for sub_item in item:
                self._include_nulls(request_fields, sub_item, parent_path=parent_path)
        elif isinstance(item, dict):
            for key, sub_level in request_fields.items():
                try:
                    sub_item = item[key]
                except KeyError:
                    # Element is missing
                    if not parent_path and key in self.top_level_array_fields:
                        # Array fields can't be expanded.
                        item[key] = []
                        continue

                    if not sub_level:
                        # This is a leaf node
                        # None for object, string, etc..
                        item[key] = None
                        continue

                    # New item is empty object, will be filled with its keys.
                    sub_item = item.setdefault(key, {})

                if sub_level:
                    self._include_nulls(
                        sub_level,
                        sub_item,
                        parent_path=parent_path + (key,),
                    )


def group_dotted_names(dotted_field_names: Iterable[str]) -> DictOfDicts:
    """Convert a list of dotted names to tree."""
    result = {}
    for dotted_name in dotted_field_names:
        tree_level = result
        for path_item in dotted_name.split("."):
            tree_level = tree_level.setdefault(path_item, {})
    return result
