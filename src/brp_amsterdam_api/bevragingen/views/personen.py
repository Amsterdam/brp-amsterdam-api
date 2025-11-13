import logging

from django.conf import settings
from rest_framework import status
from rest_framework.exceptions import APIException

from brp_amsterdam_api.bevragingen import fields, types
from brp_amsterdam_api.bevragingen.exceptions import ProblemJsonException
from brp_amsterdam_api.bevragingen.permissions import ParameterPolicy

from .base import BaseHealthCheckView, BaseProxyView, audit_log, group_dotted_names

logger = logging.getLogger(__name__)

GEMEENTE_AMSTERDAM_CODE = "0363"

SEARCH_ZIPCODE_NUMBER = "ZoekMetPostcodeEnHuisnummer"

SEARCH_INCLUDE_DECEASED = {
    "ZoekMetAdresseerbaarObjectIdentificatie",
    "ZoekMetGeslachtsnaamEnGeboortedatum",
    "ZoekMetNaamEnGemeenteVanInschrijving",
    "ZoekMetNummeraanduidingIdentificatie",
    "ZoekMetPostcodeEnHuisnummer",
    "ZoekMetStraatHuisnummerEnGemeenteVanInschrijving",
}

SEARCH_ONLY_IN_AMSTERDAM = {
    "ZoekMetStraatHuisnummerEnGemeenteVanInschrijving",
    "ZoekMetNummeraanduidingIdentificatie",
    "ZoekMetAdresseerbaarObjectIdentificatie",
    "ZoekMetNaamEnGemeenteVanInschrijving",
}

SCOPE_NATIONWIDE = "benk-brp-landelijk"
SCOPE_INCLUDE_DECEASED = "benk-brp-inclusief-overledenen"
SCOPE_ALLOW_CONFIDENTIAL_PERSONS = "benk-brp-inclusief-geheim"
SCOPE_SEARCH_POSTCODE = "benk-brp-zoekvraag-postcode-huisnummer"
SCOPE_SEARCH_POSTCODE_NATIONWIDE = "benk-brp-zoekvraag-postcode-huisnummer-landelijk"

# Which fields are allowed per type
ALL_FIELD_NAMES = fields.read_config("rvig_brp_api/personen/fields-Persoon.csv")
FILTERED = fields.read_config("rvig_brp_api/personen/fields-filtered-Persoon.csv")
FILTERED_MIN = fields.read_config("rvig_brp_api/personen/fields-filtered-PersoonBeperkt.csv")

# Which fields are allowed for each scope
SCOPES_FOR_FIELDS = fields.read_dataset_fields_files(
    "dataset_fields/personen/*.txt", accepted_field_names=ALL_FIELD_NAMES
)


class BrpPersonenHealthView(BaseHealthCheckView):
    """View to check backend access."""

    throttle_scope = "personen:health"
    endpoint_url = settings.BRP_PERSONEN_URL


class BrpPersonenView(BaseProxyView):
    """View that proxies RvIG BRP API 'personen' (persons).

    See: https://brp-api.github.io/Haal-Centraal-BRP-bevragen/

    The while OpenAPI spec for the original endpoint can be found
    at: https://raw.githubusercontent.com/BRP-API/Haal-Centraal-BRP-bevragen/master/specificatie/resolved/openapi.yaml

    This endpoint has some small differences; the "fields" parameter is not required.
    The request is mostly proxied as-is, and some parameters get default values
    based on the user role.
    """

    service_log_id = "personen"
    endpoint_url = settings.BRP_PERSONEN_URL

    # Require extra scopes
    needed_scopes = {"benk-brp-personen-api"}

    possible_fields_by_type = {
        "RaadpleegMetBurgerservicenummer": ALL_FIELD_NAMES,
        "ZoekMetAdresseerbaarObjectIdentificatie": FILTERED_MIN,
        "ZoekMetGeslachtsnaamEnGeboortedatum": FILTERED_MIN,
        "ZoekMetNaamEnGemeenteVanInschrijving": FILTERED_MIN,
        "ZoekMetNummeraanduidingIdentificatie": FILTERED_MIN,
        "ZoekMetPostcodeEnHuisnummer": FILTERED_MIN,
        "ZoekMetStraatHuisnummerEnGemeenteVanInschrijving": FILTERED_MIN,
    }

    always_insert_id_fields = ("aNummer", "burgerservicenummer")
    top_level_array_fields = [
        # Hard-coded list here of all array fields (which shouldn't get null-defaults).
        # This is based on the output of the get-openapi.py script.
        "ouders",
        "kinderen",
        "nationaliteiten",
        "partners",
        "gezag",
    ]

    # A quick dictionary to automate permission-based access to certain filter parameters.
    parameter_ruleset = {
        "type": ParameterPolicy(
            scopes_for_values={
                "RaadpleegMetBurgerservicenummer": {
                    "benk-brp-zoekvraag-bsn",
                },
                "ZoekMetGeslachtsnaamEnGeboortedatum": {
                    "benk-brp-zoekvraag-geslachtsnaam-geboortedatum"
                },
                "ZoekMetNaamEnGemeenteVanInschrijving": {
                    "benk-brp-zoekvraag-naam-gemeente",
                },
                "ZoekMetAdresseerbaarObjectIdentificatie": {
                    "benk-brp-zoekvraag-adresseerbaar-object"
                },
                "ZoekMetNummeraanduidingIdentificatie": {
                    "benk-brp-zoekvraag-nummeraanduiding",
                },
                "ZoekMetPostcodeEnHuisnummer": {
                    SCOPE_SEARCH_POSTCODE,
                    SCOPE_SEARCH_POSTCODE_NATIONWIDE,
                },
                "ZoekMetStraatHuisnummerEnGemeenteVanInschrijving": {
                    "benk-brp-zoekvraag-straatnaam-huisnummer"
                },
            }
        ),
        "fields": ParameterPolicy(
            # - Fields/field groups that can be requested for a search:
            #   https://raw.githubusercontent.com/BRP-API/Haal-Centraal-BRP-bevragen/master/features/fields-filtered-PersoonBeperkt.csv
            # - Fields/field groups that can be requested a single person by their BSN:
            #   https://raw.githubusercontent.com/BRP-API/Haal-Centraal-BRP-bevragen/master/features/fields-filtered-Persoon.csv
            # - Some fields will be included automatically:
            #   https://brp-api.github.io/Haal-Centraal-BRP-bevragen/v2/features-overzicht#standaard-geleverde-velden
            scopes_for_values=(
                # Declare all known fields which are supported with a deny-permission (None).
                # This avoids generating a '400 Bad Request' for unknown fieldnames
                # instead of '403 Permission Denied' responses.
                dict.fromkeys(sorted(ALL_FIELD_NAMES))
                # And override those with the configurations for each known role / "gegevensset".
                | SCOPES_FOR_FIELDS
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
        # Note: Using 'verblijfplaats' in the search will be limited to NL-only results
        # when it's combined with fields=verblijfplaatsBinnenland instead of fields=verblijfplaats.
        "verblijfplaats": ParameterPolicy.allow_all,
        "nummeraanduidingIdentificatie": ParameterPolicy.allow_all,
        "adresseerbaarObjectIdentificatie": ParameterPolicy.allow_all,
        "burgerservicenummer": ParameterPolicy.for_all_values({"benk-brp-zoekvraag-bsn"}),
        "inclusiefOverledenPersonen": ParameterPolicy(
            scopes_for_values={
                True: {SCOPE_INCLUDE_DECEASED},
                False: ParameterPolicy.allow_value,
            }
        ),
        "gemeenteVanInschrijving": ParameterPolicy(
            {
                # ok to include ?gemeenteVanInschrijving=0363
                GEMEENTE_AMSTERDAM_CODE: ParameterPolicy.allow_value
            },
            default_scope={SCOPE_NATIONWIDE},
        ),
    }

    # Special rules for some query types:
    disallow_nationwide_municipality_code = {
        **parameter_ruleset,
        # Disallow searching outside Amsterdam for postcode search.
        "gemeenteVanInschrijving": ParameterPolicy(
            {GEMEENTE_AMSTERDAM_CODE: ParameterPolicy.allow_value},
        ),
    }

    # List comprehension doesn't work here, so we'll use a for loop
    # see https://docs.python.org/3/reference/executionmodel.html#resolution-of-names
    parameter_ruleset_by_type = {}
    for request_type in SEARCH_ONLY_IN_AMSTERDAM:
        parameter_ruleset_by_type[request_type] = disallow_nationwide_municipality_code

    parameter_ruleset_by_type["ZoekMetPostcodeEnHuisnummer"] = {
        **parameter_ruleset,
        # Also allow searching outside Amsterdam for postcode search if both scopes are present
        "gemeenteVanInschrijving": ParameterPolicy(
            {GEMEENTE_AMSTERDAM_CODE: ParameterPolicy.allow_value},
            default_scope={SCOPE_SEARCH_POSTCODE_NATIONWIDE},
        ),
    }

    def get_parameter_ruleset(self, hc_request: types.PersonenQuery) -> dict[str, ParameterPolicy]:
        """Allow a different parameter ruleset for some type of requests."""
        return self.parameter_ruleset_by_type.get(hc_request.get("type"), self.parameter_ruleset)

    def log_access_granted(
        self,
        request,
        hc_request: types.PersonenQuery,
        hc_response: types.PersonenResponse | None,
        final_response: types.PersonenResponse | None,
        needed_scopes: set[str],
        exception: OSError | APIException | None = None,
    ) -> None:
        """Extend logging to also include each BSN that was returned in the response"""
        super().log_access_granted(
            request, hc_request, hc_response, final_response, needed_scopes, exception
        )

        if exception is None:
            # Separate log message for every person that's being accessed.
            for persoon in hc_response["personen"]:
                msg_params = {}
                extra = {
                    "request": request.data,
                    "hcRequest": hc_request,
                    "hcResponse": final_response or hc_response,
                }
                msg = ["User %(upn)s retrieved using '%(service)s.%(queryType)s':"]
                for id_field in self.always_insert_id_fields:
                    msg_params[id_field] = persoon.get(id_field, "?")
                    extra[id_field] = persoon.get(id_field, None)
                    msg.append(f"{id_field}=%({id_field})s")

                audit_log.info(
                    # Visible log message
                    " ".join(msg),
                    {
                        "service": self.service_log_id,
                        "queryType": hc_request["type"],
                        "upn": self.upn,
                        **msg_params,
                    },
                    # Extra JSON fields for log querying
                    extra={
                        **self.default_log_fields,
                        **extra,
                    },
                )

    def transform_request(self, hc_request: types.PersonenQuery) -> None:
        """Extra rules before passing the request to RvIG BRP API"""
        if "fields" not in hc_request:
            self._add_fields_filter(hc_request)

        if "gemeenteVanInschrijving" not in hc_request and (
            SCOPE_NATIONWIDE not in self.user_scopes
            or hc_request["type"] in SEARCH_ONLY_IN_AMSTERDAM
            or (
                SCOPE_SEARCH_POSTCODE in self.user_scopes
                and hc_request["type"] == "ZoekMetPostcodeEnHuisnummer"
            )
        ):
            self._add_municipality_filter(hc_request)

        if (
            SCOPE_INCLUDE_DECEASED in self.user_scopes
            and hc_request["type"] in SEARCH_INCLUDE_DECEASED
            and "inclusiefOverledenPersonen" not in hc_request
        ):
            self._add_deceased_filter(hc_request)

        # Always need to log aNummer/BSN, so make sure it's requested too.
        self.inserted_id_fields = []
        self._add_identifier_fields(hc_request)

    def _add_fields_filter(self, hc_request: types.PersonenQuery) -> None:
        """Determine all values for the "fields" parameter that the user has access to.

        This value is used when no default is given.

        :param query_type: The "zoekvraag/doelbinding" (the "type" parameter in the request).
        """
        allowed_by_scope = self.parameter_ruleset["fields"].get_allowed_values(self.user_scopes)
        allowed_by_type = self.possible_fields_by_type.get(hc_request["type"], None)

        # The sorting is done to have consistent logging.
        allowed_fields = sorted(
            set(allowed_by_type).intersection(allowed_by_scope)
            if allowed_by_type is not None
            else allowed_by_scope
        )

        if not allowed_fields:
            audit_log.info(
                "Denied access to '%(service)s' no allowed values for 'fields'",
                {"service": self.service_log_id},
                extra={
                    **self.default_log_fields,
                    "field": "fields",
                    "values": [],
                },
            )
            raise ProblemJsonException(
                title="U bent niet geautoriseerd voor deze operatie.",
                detail="U bent niet geautoriseerd voor een gegevensset bij deze operatie.",
                code="permissionDenied",  # Same as what RvIG BRP API would do.
                status=status.HTTP_403_FORBIDDEN,
            )

        # When no 'fields' parameter is given, pass all allowed options
        logging.debug("Auto-generating 'fields' parameter based on user scopes")
        hc_request["fields"] = fields.compact_fields_values(allowed_fields)

    def _add_municipality_filter(self, hc_request: types.PersonenQuery) -> None:
        """Restrict the search to a single municipality."""
        # If the use may only search in Amsterdam, enforce that.
        # if a different value is set, it will be handled by the permission check later.
        if hc_request["type"] not in [
            "ZoekMetPostcodeEnHuisnummer",
            "ZoekMetStraatHuisnummerEnGemeenteVanInschrijving",
            "ZoekMetNummeraanduidingIdentificatie",
            "ZoekMetAdresseerbaarObjectIdentificatie",
            "ZoekMetNaamEnGemeenteVanInschrijving",
        ]:
            # Only log this line for types which could be used for nationwide search
            logging.debug(
                "User doesn't have %s scope, limiting results to gemeenteVanInschrijving=%s",
                SCOPE_NATIONWIDE,
                GEMEENTE_AMSTERDAM_CODE,
            )
        hc_request["gemeenteVanInschrijving"] = GEMEENTE_AMSTERDAM_CODE

    def _add_deceased_filter(self, hc_request: types.PersonenQuery) -> None:
        """When the user profile may access deceased persons, include that."""
        logging.debug(
            "User has %s scope, adding inclusiefOverledenPersonen=true", SCOPE_INCLUDE_DECEASED
        )
        hc_request["inclusiefOverledenPersonen"] = True

    def _add_identifier_fields(self, hc_request: types.PersonenQuery) -> None:
        """Add identifier fields in the request.
        These are needed to perform logging statements.
        When the user didn't request them (or didn't have access),
        they will be requested internally, and removed before the response returns.
        """
        query_type = hc_request["type"]
        fields_by_type = self.possible_fields_by_type.get(query_type) or []
        for id_field in self.always_insert_id_fields:  # Not including nested fields for now
            if id_field not in hc_request["fields"] and id_field in fields_by_type:
                hc_request["fields"].append(id_field)
                self.inserted_id_fields.append(id_field)
                logging.debug(
                    "User doesn't request ID field %s, only adding for internal logging", id_field
                )

    def transform_response(
        self,
        hc_request: types.PersonenQuery,
        hc_response: types.PersonenResponse,
    ) -> None:
        """Extra rules before passing the response to the client."""
        super().transform_response(hc_request, hc_response)  # rewrite links

        # Remove persons that the calling organisation may not see.
        if SCOPE_ALLOW_CONFIDENTIAL_PERSONS not in self.user_scopes:
            self._hide_confidential_persons(hc_response)

        # Remove the extra fields that were only inserted to have a BSN/aNummer in the logging,
        # even through the user has no access to these fields.
        if self.inserted_id_fields:
            self._hide_inserted_identifiers(hc_request, hc_response)

    def _hide_confidential_persons(self, hc_response: types.PersonenResponse) -> None:
        """
        If the user may not see persons with confidential data,
        hide those persons in the response.

        This is a flag that data may not be shared with
        organisations such as churches, sports clubs and charities.

        Based on:
        https://github.com/BRP-API/Haal-Centraal-BRP-bevragen/issues/1756
        https://github.com/BRP-API/Haal-Centraal-BRP-bevragen/issues/1857
        """
        personen = [
            persoon
            for persoon in hc_response["personen"]
            if not int(persoon.get("geheimhoudingPersoonsgegevens", 0))  # "1" in demo data
        ]
        num_hidden = len(hc_response["personen"]) - len(personen)
        if num_hidden:
            logging.debug(
                "Removed %d persons from response"
                " (missing scope %s for to view 'geheimhoudingPersoonsgegevens')",
                num_hidden,
                SCOPE_ALLOW_CONFIDENTIAL_PERSONS,
            )

        hc_response["personen"] = personen

    def _hide_inserted_identifiers(self, hc_request, hc_response: types.PersonenResponse) -> None:
        """Any additional identifiers that we requested internally, need to be removed.
        The client was not allowed to see these.
        """
        logging.debug(
            "Removing additional identifier fields from response: %s",
            ",".join(self.inserted_id_fields),
        )
        for persoon in hc_response["personen"]:
            for id_field in self.inserted_id_fields:
                persoon.pop(id_field, None)

        # Also clean up from request before logging it.
        # Also makes sure the null-inserted fields won't include these.
        for id_field in self.inserted_id_fields:
            hc_request["fields"].remove(id_field)

    def _insert_null_values(
        self, hc_request: types.PersonenQuery, hc_response: types.PersonenResponse
    ) -> None:
        """Insert any null values that the user does have access to.
        This allows the client to distinguish between having 'no value' instead of 'no access'.
        """
        request_fields = group_dotted_names(hc_request["fields"])
        self._include_nulls(request_fields, hc_response["personen"])
