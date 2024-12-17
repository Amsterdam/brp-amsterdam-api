import logging

import orjson
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse
from django.urls import reverse
from rest_framework import status
from rest_framework.request import Request
from rest_framework.views import APIView

from . import fields, permissions
from .client import HaalCentraalClient, HaalCentraalResponse
from .exceptions import ProblemJsonException
from .permissions import ParameterPolicy, audit_log

logger = logging.getLogger(__name__)

GEMEENTE_AMSTERDAM_CODE = "0363"
ALLOW_VALUE = set()  # no scopes

SCOPE_NATIONWIDE = "benk-brp-landelijk"
SCOPE_ALLOW_CONFIDENTIAL_PERSONS = "benk-brp-geheimhouding-persoonsgegevens"


class BaseProxyView(APIView):
    """View that proxies Haal Centraal BRP.

    This is a pass-through proxy, but with authorization and extra restrictions added.
    The subclasses implement the variations between Haal Centraal endpoints.
    """

    #: Define which additional scopes are needed
    client_class = HaalCentraalClient

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

    def post(self, request: Request, *args, **kwargs):
        """Handle the incoming POST request.
        Basic checks (such as content-type validation) are already done by REST Framework.
        The API uses POST so the logs won't include personally identifiable information (PII).
        """
        # Check the request
        self.user_scopes = set(request.get_token_scopes)
        self.user_id = request.get_token_claims.get("email", request.get_token_subject)
        hc_request = request.data.copy()

        self.transform_request(hc_request)
        all_needed_scopes = permissions.validate_parameters(
            self.parameter_ruleset,
            hc_request,
            self.user_scopes,
            service_log_id=self.service_log_id,
        )

        # Proxy to Haal Centraal
        hc_response = self.client.call(hc_request)

        # Rewrite the response to pagination still works.
        # (currently in in-place)
        self.transform_response(hc_response.data)

        # Post it to audit logging
        self.log_access(
            request,
            hc_request,
            hc_response,
            needed_scopes=all_needed_scopes,
        )

        # And return it.
        return HttpResponse(
            orjson.dumps(hc_response.data),
            content_type=hc_response.headers.get("Content-Type"),
        )

    def log_access(
        self,
        request,
        hc_request: dict,
        hc_response: HaalCentraalResponse,
        needed_scopes: set[str],
    ) -> None:
        """Perform the audit logging for the request/response.

        This is a very basic global logging.
        Per service type, it may need more refinement.
        """
        # user.AuthenticatedId is already added globally.
        # TODO:
        # - Per record (in lijst) een log melding doen.
        # - afnemerindicatie (client certificaat)
        # - session ID van afnemende applicatie.
        # - A-nummer in de response
        audit_log.info(
            "Access granted to '%(service)s' for '%(user)s, full request/response",
            {
                "service": self.service_log_id,
                "user": self.user_id,
            },
            extra={
                "service": self.service_log_id,
                "user": self.user_id,
                "granted": sorted(self.user_scopes),
                "needed": sorted(needed_scopes),
                "request": request.data,
                "hc_request": hc_request,
                "hc_response": hc_response.data,
            },
        )

    def transform_request(self, hc_request: dict) -> None:
        """This method can be overwritten to provide extra request parameter handling per endpoint.
        It may perform in-place replacements of the request.
        """

    def transform_response(self, hc_response: dict | list) -> None:
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


class BaseProxyFieldsView(BaseProxyView):
    """Base proxy view that also has a default 'fields' parameter.
    Could also have been a mixin, but this seems clear too."""

    #: Tell which fields are allowed per type (used to have a default list).
    possible_fields_by_type: dict[str, set[str]] = {}

    def get_allowed_fields(self, query_type: str) -> list[str]:
        """Determine all values for the "fields" parameter that the user has access to.

        This value is used when no default is given.

        :param query_type: The "zoekvraag/doelbinding" (the "type" parameter in the request).
        """
        allowed_by_scope = self.parameter_ruleset["fields"].get_allowed_values(self.user_scopes)
        allowed_by_type = self.possible_fields_by_type.get(query_type, None)

        allowed_fields = (
            list(set(allowed_by_type).intersection(allowed_by_scope))
            if allowed_by_type is not None
            else allowed_by_scope
        )

        if not allowed_fields:
            audit_log.info(
                "Denied access to '%(service)s' no allowed values for 'fields'",
                {"service": self.service_log_id},
                extra={
                    "service": self.service_log_id,
                    "field": "fields",
                    "values": [],
                    "granted": sorted(self.user_scopes),
                },
            )
            raise ProblemJsonException(
                title="U bent niet geautoriseerd voor deze operatie.",
                detail="U bent niet geautoriseerd voor een gegevensset bij deze operatie.",
                code="permissionDenied",  # Same as what Haal Centraal would do.
                status=status.HTTP_403_FORBIDDEN,
            )

        return fields.compact_fields_values(allowed_fields)

    def transform_request(self, hc_request):
        if "fields" not in hc_request and "type" in hc_request:
            # When no 'fields' parameter is given, pass all allowed options
            hc_request["fields"] = self.get_allowed_fields(hc_request["type"])


class BrpPersonenView(BaseProxyFieldsView):
    """View that proxies Haal Centraal BRP 'personen' (persons).

    See: https://brp-api.github.io/Haal-Centraal-BRP-bevragen/
    """

    service_log_id = "personen"
    endpoint_url = settings.HAAL_CENTRAAL_BRP_URL

    # Require extra scopes
    needed_scopes = {"benk-brp-api"}

    # Which fields are allowed per type
    ALL_FIELD_NAMES = fields.read_config("haal_centraal/personen/fields-Persoon.csv")
    FILTERED = fields.read_config("haal_centraal/personen/fields-filtered-Persoon.csv")
    FILTERED_MIN = fields.read_config("haal_centraal/personen/fields-filtered-PersoonBeperkt.csv")

    possible_fields_by_type = {
        "RaadpleegMetBurgerservicenummer": ALL_FIELD_NAMES,
        "ZoekMetAdresseerbaarObjectIdentificatie": FILTERED,
        "ZoekMetGeslachtsnaamEnGeboortedatum": FILTERED_MIN,
        "ZoekMetNaamEnGemeenteVanInschrijving": FILTERED_MIN,
        "ZoekMetNummeraanduidingIdentificatie": FILTERED_MIN,
        "ZoekMetPostcodeEnHuisnummer": FILTERED_MIN,
        "ZoekMetStraatHuisnummerEnGemeenteVanInschrijving": FILTERED_MIN,
    }

    # A quick dictionary to automate permission-based access to certain filter parameters.
    parameter_ruleset = {
        "type": ParameterPolicy(
            scopes_for_values={
                "RaadpleegMetBurgerservicenummer": {"benk-brp-zoekvraag-bsn"},
                "ZoekMetGeslachtsnaamEnGeboortedatum": {
                    "benk-brp-zoekvraag-geslachtsnaam-geboortedatum"
                },
                "ZoekMetNaamEnGemeenteVanInschrijving": {"BRP/zoek-naam-gemeente"},
                "ZoekMetAdresseerbaarObjectIdentificatie": {"BRP/zoek-adres-id"},
                "ZoekMetNummeraanduidingIdentificatie": {"BRP/zoek-nummeraand-id"},
                "ZoekMetPostcodeEnHuisnummer": {"benk-brp-zoekvraag-postcode-huisnummer"},
                "ZoekMetStraatHuisnummerEnGemeenteVanInschrijving": {"BRP/zoek-straat"},
            }
        ),
        "fields": ParameterPolicy(
            # - Fields/field groups that can be requested for a search:
            #   https://raw.githubusercontent.com/BRP-API/Haal-Centraal-BRP-bevragen/master/features/fields-filtered-PersoonBeperkt.csv
            # - Fields/field groups that can be requested a single person by their BSN:
            #   https://raw.githubusercontent.com/BRP-API/Haal-Centraal-BRP-bevragen/master/features/fields-filtered-Persoon.csv
            scopes_for_values=(
                # Declare all known fields which are supported with a deny-permission (None).
                # This avoids generating a '400 Bad Request' for unknown fieldnames
                # instead of '403 Permission Denied' responses.
                {field_name: None for field_name in sorted(ALL_FIELD_NAMES)}
                # And override those with the configurations for each known role / "gegevensset".
                | fields.read_dataset_fields_files(
                    "dataset_fields/personen/*.txt", accepted_field_names=ALL_FIELD_NAMES
                )
            ),
        ),
        # All possible search parameters are named here,
        # to avoid passing through a flag that allows more access.
        # See: https://brp-api.github.io/Haal-Centraal-BRP-bevragen/v2/redoc#tag/Personen/operation/Personen
        "geboortedatum": ParameterPolicy.allow_all,
        "geslachtsnaam": ParameterPolicy.allow_all,
        "geslacht": ParameterPolicy.allow_all,
        "voorvoegsel": ParameterPolicy.allow_all,
        "voornamen": ParameterPolicy.allow_all,
        "straat": ParameterPolicy.allow_all,
        "huisletter": ParameterPolicy.allow_all,
        "huisnummer": ParameterPolicy.allow_all,
        "huisnummertoevoeging": ParameterPolicy.allow_all,
        "postcode": ParameterPolicy.allow_all,
        "nummeraanduidingIdentificatie": ParameterPolicy.allow_all,
        "adresseerbaarObjectIdentificatie": ParameterPolicy.allow_all,
        "verblijfplaats": ParameterPolicy.for_all_values({"BRP/in-buitenland"}),
        "burgerservicenummer": ParameterPolicy.for_all_values({"benk-brp-zoekvraag-bsn"}),
        "inclusiefOverledenPersonen": ParameterPolicy(
            scopes_for_values={
                "true": {"benk-brp-inclusief-overledenen"},
                "false": ALLOW_VALUE,
            }
        ),
        "gemeenteVanInschrijving": ParameterPolicy(
            # NOTE: no benk-brp-amsterdam ?
            {GEMEENTE_AMSTERDAM_CODE: ALLOW_VALUE},  # ok to include ?gemeenteVanInschrijving=0363
            default_scope={SCOPE_NATIONWIDE},
        ),
    }

    def transform_request(self, hc_request: dict) -> None:
        """Extra rules before passing the request to Haal Centraal"""
        super().transform_request(hc_request)  # add 'fields'

        if SCOPE_NATIONWIDE not in self.user_scopes:
            # If the use may only search in Amsterdam, enforce that.
            # if a different value is set, it will be handled by the permission check later.
            hc_request.setdefault("gemeenteVanInschrijving", GEMEENTE_AMSTERDAM_CODE)

    def transform_response(self, hc_response: dict | list) -> None:
        """Extra rules before passing the response to the client."""
        super().transform_response(hc_response)  # rewrite links

        if SCOPE_ALLOW_CONFIDENTIAL_PERSONS not in self.user_scopes:
            # If the user may not see persons with confidential data,
            # hide those persons in the response. Based on:
            # https://github.com/BRP-API/Haal-Centraal-BRP-bevragen/issues/1756
            # https://github.com/BRP-API/Haal-Centraal-BRP-bevragen/issues/1857
            hc_response["personen"] = [
                persoon
                for persoon in hc_response["personen"]
                if not int(persoon.get("geheimhoudingPersoonsgegevens", 0))  # "1" in demo data
            ]


class BrpBewoningenView(BaseProxyView):
    """View to proxy Haal Centraal Bewoning (ocupancy).

    See: https://brp-api.github.io/Haal-Centraal-BRP-bewoning/
    """

    service_log_id = "bewoningen"
    endpoint_url = settings.HAAL_CENTRAAL_BRP_BEWONINGEN_URL

    # Require extra scopes
    needed_scopes = {"benk-brp-api"}

    # Validate the access to various parameters:
    parameter_ruleset = {
        "type": ParameterPolicy(
            scopes_for_values={
                "BewoningMetPeildatum": {"BRP/zoek-bewoningen"},
                "BewoningMetPeriode": {"BRP/zoek-bewoningen"},
            }
        ),
        "adresseerbaarObjectIdentificatie": ParameterPolicy.allow_all,  # used for both types.
        "peildatum": ParameterPolicy.allow_all,  # for BewoningMetPeildatum
        "datumTot": ParameterPolicy.allow_all,  # for BewoningMetPeriode
        "datumVan": ParameterPolicy.allow_all,  # for BewoningMetPeriode
    }


class BrpVerblijfsplaatsHistorieView(BaseProxyView):
    """View that proxies Haal Centraal BRP Verblijfplaatshistorie of a person (residence history).

    See: https://brp-api.github.io/Haal-Centraal-BRP-historie-bevragen/
    """

    service_log_id = "verblijfsplaatshistorie"
    endpoint_url = settings.HAAL_CENTRAAL_BRP_VERBLIJFSPLAATS_HISTORIE_URL

    # Require extra scopes
    needed_scopes = {"benk-brp-api"}

    # A quick dictionary to automate permission-based access to certain filter parameters.
    parameter_ruleset = {
        "type": ParameterPolicy(
            scopes_for_values={
                "RaadpleegMetPeildatum": {"BRP/zoek-historie"},
                "RaadpleegMetPeriode": {"BRP/zoek-historie"},
            }
        ),
        "burgerservicenummer": ParameterPolicy.allow_all,  # used for both request types.
        "peildatum": ParameterPolicy.allow_all,  # for RaadpleegMetPeildatum
        "datumTot": ParameterPolicy.allow_all,  # for RaadpleegMetPeriode
        "datumVan": ParameterPolicy.allow_all,  # for RaadpleegMetPeriode
    }


class ReisdocumentenView(BaseProxyFieldsView):
    """View to proxy Haal Centraal Reisdocumenten (travel documents).

    See: https://brp-api.github.io/Haal-Centraal-Reisdocumenten-bevragen/
    """

    service_log_id = "reisdocumenten"
    endpoint_url = settings.HAAL_CENTRAAL_REISDOCUMENTEN_URL

    # Require extra scopes
    needed_scopes = {"benk-brp-api"}

    # A quick dictionary to automate permission-based access to certain filter parameters.
    parameter_ruleset = {
        "type": ParameterPolicy(
            scopes_for_values={
                "RaadpleegMetReisdocumentnummer": {"BRP/zoek-doc"},
                "ZoekMetBurgerservicenummer": {"BRP/zoek-doc-bsn"},
            }
        ),
        "fields": ParameterPolicy(
            scopes_for_values={
                # Extracted from redoc and
                # https://github.com/BRP-API/Haal-Centraal-Reisdocumenten-bevragen/blob/master/src/Reisdocument.Validatie/Validators/ReisdocumentenQueryValidator.cs
                "reisdocumentnummer": {"BRP/x"},
                "soort": {"BRP/x"},
                "soort.*": {"BRP/x"},
                "houder": {"BRP/x"},
                "houder.*": {"BRP/x"},
                "datumEindeGeldigheid": {"BRP/x"},
                "datumEindeGeldigheid.*": {"BRP/x"},
                "inhoudingOfVermissing": {"BRP/x"},
                "inhoudingOfVermissing.*": {"BRP/x"},
            }
        ),
        "reisdocumentnummer": ParameterPolicy(
            # for RaadpleegMetReisdocumentnummer
            default_scope={"BRP/zoek-doc"}
        ),
        "burgerservicenummer": ParameterPolicy(
            # for ZoekMetBurgerservicenummer
            default_scope={"BRP/zoek-doc-bsn"}
        ),
    }
