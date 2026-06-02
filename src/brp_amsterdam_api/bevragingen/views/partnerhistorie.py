import logging

from django.conf import settings
from rest_framework import status
from rest_framework.exceptions import APIException
from rest_framework.request import Request

from brp_amsterdam_api.bevragingen import fields, types
from brp_amsterdam_api.bevragingen.clients.brp_v import (
    BrpVAdhocServiceClient,
)
from brp_amsterdam_api.bevragingen.exceptions import ProblemJsonException
from brp_amsterdam_api.bevragingen.permissions import ParameterPolicy

from .base import BaseProxyView, audit_log, group_dotted_names

ALL_FIELD_NAMES = fields.read_config("rvig_brp_api/personen/fields-Persoon.csv")

# Which fields are allowed for each scope, specified for prod or non-prod
env_dir = "prd" if settings.ENVIRONMENT == "prd" else "npr"
SCOPES_FOR_FIELDS = fields.read_dataset_fields_files(
    f"dataset_fields/{env_dir}/personen/*.txt", accepted_field_names=ALL_FIELD_NAMES
)

# Fields we currently don't have access to for the in the Ad Hoc Service.
# Can be removed once the BRP API supports partner history
DISALLOWED_FIELDS = [
    "partners.soortVerbintenis",
    "partners.geslacht",
    "partners.geboorte.plaats",
    "partners.geboorte.land",
    "partners.aangaanHuwelijkPartnerschap.plaats",
    "partners.aangaanHuwelijkPartnerschap.land",
    "partners.ontbindingHuwelijkPartnerschap.plaats",
    "partners.ontbindingHuwelijkPartnerschap.land",
]

# We need to match the field names a scope is allowed to request to the partnerhistorie field names
SCOPES_FOR_FIELDS = {
    field.replace("partners.", ""): scopes
    for field, scopes in SCOPES_FOR_FIELDS.items()
    if field.startswith("partners.") and field not in DISALLOWED_FIELDS
}


class BrpPartnerhistorieView(BaseProxyView):
    """View that proxies RvIG BRP API Verblijfplaatshistorie of a person (residence history).

    See: https://brp-api.github.io/Haal-Centraal-BRP-historie-bevragen/
    """

    client_class = BrpVAdhocServiceClient

    service_log_id = "partnerhistorie"
    endpoint_url = settings.BRP_PARTNERHISTORIE_URL

    # Require extra scopes
    needed_scopes = {"benk-brp-partnerhistorie-api"}

    # A quick dictionary to automate permission-based access to certain filter parameters.
    parameter_ruleset = {
        "type": ParameterPolicy(
            scopes_for_values={
                "RaadpleegMetBurgerservicenummer": {"benk-brp-partnerhistorie-api"},
            }
        ),
        "fields": ParameterPolicy(
            scopes_for_values=(
                # Declare all known fields which are supported with a deny-permission (None).
                # This avoids generating a '400 Bad Request' for unknown fieldnames
                # instead of '403 Permission Denied' responses.
                dict.fromkeys(sorted(ALL_FIELD_NAMES))
                # And override those with the configurations for each known role / "gegevensset".
                | SCOPES_FOR_FIELDS
            ),
        ),
        "burgerservicenummer": ParameterPolicy.allow_all,  # used for both request types.
    }

    always_insert_id_fields = ("burgerservicenummer",)
    top_level_array_fields = ["partnerhistorie"]

    def get_client(self) -> BrpVAdhocServiceClient:
        """Provide the API client class. This can be overwritten per view if needed."""
        return self.client_class(
            endpoint_url=self.endpoint_url,
            user=settings.BRP_V_ADHOC_USER,
            password=settings.BRP_V_ADHOC_PASSWORD,
            cert_file=settings.BRP_MTLS_CERT_FILE,
            key_file=settings.BRP_MTLS_KEY_FILE,
        )

    def initial(self, request: Request, *args, **kwargs):
        # Perform authorization, permission checks and throttles.
        super().initial(request, *args, **kwargs)

        self.client = self.get_client()

    def transform_request(self, hc_request: types.PartnerhistorieQuery) -> None:
        """Extra rules before passing the request to RvIG BRP-V Adhoc Service"""
        if "fields" not in hc_request:
            self._add_fields_filter(hc_request)

        # Always need to log aNummer/BSN, so make sure it's requested too.
        self.inserted_id_fields = []
        self._add_identifier_fields(hc_request)

    def transform_response(
        self, hc_request: types.BaseQuery, hc_response: types.BaseResponse | list
    ) -> None:
        super().transform_response(hc_request, hc_response)  # add null values if needed

        # Remove the extra fields that were only inserted to have a BSN/aNummer in the logging,
        # even through the user has no access to these fields.
        if self.inserted_id_fields:
            self._hide_inserted_identifiers(hc_request, hc_response)

    def log_access_granted(
        self,
        request,
        hc_request: types.BaseQuery,
        hc_response: types.BaseResponse | None,
        final_response: types.BaseResponse | None,
        needed_scopes: set[str],
        exception: OSError | APIException | None = None,
        extra: dict | None = None,
    ) -> None:
        """Extend logging to also include each BSN that was returned in the response"""

        if exception is None:
            # Create arrays of BSNs and aNummers for every person that's being accessed.
            extra = {}
            for id_field in self.always_insert_id_fields:
                extra[f"{id_field}s"] = []
                for partner in hc_response["partnerhistorie"]:
                    value = partner.get(id_field, None)
                    if value and value not in extra[f"{id_field}s"]:
                        extra[f"{id_field}s"].append(value)

            super().log_access_granted(
                request,
                hc_request,
                hc_response,
                final_response,
                needed_scopes,
                exception,
                extra=extra,
            )
            return

        super().log_access_granted(
            request, hc_request, hc_response, final_response, needed_scopes, exception
        )

    def _add_fields_filter(self, hc_request: types.PartnerhistorieQuery) -> None:
        """Determine all values for the "fields" parameter that the user has access to.

        This value is used when no default is given.

        :param query_type: The "zoekvraag/doelbinding" (the "type" parameter in the request).
        """
        allowed_fields = sorted(
            self.parameter_ruleset["fields"].get_allowed_values(self.user_scopes)
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
                code="permissionDenied",
                status=status.HTTP_403_FORBIDDEN,
            )

        # When no 'fields' parameter is given, pass all allowed options
        logging.debug("Auto-generating 'fields' parameter based on user scopes")
        hc_request["fields"] = fields.compact_fields_values(allowed_fields)

    def _add_identifier_fields(self, hc_request: types.PartnerhistorieQuery) -> None:
        """Add identifier fields in the request.
        These are needed to perform logging statements.
        When the user didn't request them (or didn't have access),
        they will be requested internally, and removed before the response returns.
        """
        for id_field in self.always_insert_id_fields:  # Not including nested fields for now
            if id_field not in hc_request["fields"]:
                hc_request["fields"].append(id_field)
                self.inserted_id_fields.append(id_field)
                logging.debug(
                    "User doesn't request ID field %s, only adding for internal logging", id_field
                )

    def _hide_inserted_identifiers(
        self, hc_request, hc_response: types.PartnerhistorieResponse
    ) -> None:
        """Any additional identifiers that we requested internally, need to be removed.
        The client was not allowed to see these.
        """
        logging.debug(
            "Removing additional identifier fields from response: %s",
            ",".join(self.inserted_id_fields),
        )
        for partner in hc_response["partnerhistorie"]:
            for id_field in self.inserted_id_fields:
                partner.pop(id_field, None)

        # Also clean up from request before logging it.
        # Also makes sure the null-inserted fields won't include these.
        for id_field in self.inserted_id_fields:
            hc_request["fields"].remove(id_field)

    def _insert_null_values(
        self, hc_request: types.PartnerhistorieQuery, hc_response: types.PartnerhistorieResponse
    ) -> None:
        """Insert any null values that the user does have access to.
        This allows the client to distinguish between having 'no value' instead of 'no access'.
        """
        request_fields = group_dotted_names(hc_request["fields"])
        self._include_nulls(request_fields, hc_response["partnerhistorie"])
