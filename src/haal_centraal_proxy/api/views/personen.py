import logging

from django.conf import settings
from rest_framework import status
from rest_framework.exceptions import APIException

from haal_centraal_proxy.api import fields
from haal_centraal_proxy.api.exceptions import ProblemJsonException
from haal_centraal_proxy.api.permissions import ParameterPolicy

from .base import BaseProxyView, audit_log

logger = logging.getLogger(__name__)

ALLOW_VALUE = set()  # no scopes

GEMEENTE_AMSTERDAM_CODE = "0363"

SCOPE_NATIONWIDE = "benk-brp-landelijk"
SCOPE_ALLOW_CONFIDENTIAL_PERSONS = "benk-brp-geheimhouding-persoonsgegevens"


class BrpPersonenView(BaseProxyView):
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

    always_insert_id_fields = ("aNummer", "burgerservicenummer")

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
        query_type = hc_request["type"]
        if "fields" not in hc_request:
            # When no 'fields' parameter is given, pass all allowed options
            logging.debug("Auto-generating 'fields' parameter based on user scopes")
            hc_request["fields"] = self.get_allowed_fields(query_type)

        if (
            SCOPE_NATIONWIDE not in self.user_scopes
            and "gemeenteVanInschrijving" not in hc_request
        ):
            # If the use may only search in Amsterdam, enforce that.
            # if a different value is set, it will be handled by the permission check later.
            logging.debug(
                "User doesn't have %s scope, limiting results to gemeenteVanInschrijving=%s",
                SCOPE_NATIONWIDE,
                GEMEENTE_AMSTERDAM_CODE,
            )
            hc_request["gemeenteVanInschrijving"] = GEMEENTE_AMSTERDAM_CODE

        # Always need to log aNummer/BSN, so make sure it's requested too.
        self.inserted_id_fields = []
        fields_by_type = self.possible_fields_by_type.get(query_type) or []
        for id_field in self.always_insert_id_fields:  # Not including nested fields for now
            if id_field not in hc_request["fields"] and id_field in fields_by_type:
                hc_request["fields"].append(id_field)
                self.inserted_id_fields.append(id_field)
                logging.debug(
                    "User doesn't request ID field %s, only adding for internal logging", id_field
                )

    def transform_response(self, hc_response: dict | list) -> None:
        """Extra rules before passing the response to the client."""
        super().transform_response(hc_response)  # rewrite links

        if SCOPE_ALLOW_CONFIDENTIAL_PERSONS not in self.user_scopes:
            # If the user may not see persons with confidential data,
            # hide those persons in the response. Based on:
            # https://github.com/BRP-API/Haal-Centraal-BRP-bevragen/issues/1756
            # https://github.com/BRP-API/Haal-Centraal-BRP-bevragen/issues/1857
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

        # Remove the extra fields that were only inserted to have a BSN/aNummer in the logging,
        # even through the user has no access to these fields.
        if self.inserted_id_fields:
            logging.debug(
                "Removing additional identifier fields from response: %s",
                ",".join(self.inserted_id_fields),
            )
            for persoon in hc_response["personen"]:
                for id_field in self.inserted_id_fields:
                    persoon.pop(id_field, None)

    def log_access_granted(
        self,
        request,
        hc_request: dict,
        hc_response: dict | None,
        final_response: dict | None,
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
                extra = {}
                msg = ["User %(user)s retrieved using '%(service)s.%(query_type)s':"]
                for id_field in self.always_insert_id_fields:
                    msg_params[id_field] = persoon.get(id_field, "?")
                    extra[id_field] = persoon.get(id_field, None)
                    msg.append(f"{id_field}=%({id_field})s")

                print(msg)
                audit_log.info(
                    # Visible log message
                    " ".join(msg),
                    {
                        "service": self.service_log_id,
                        "query_type": hc_request["type"],
                        "user": self.user_id,
                        **msg_params,
                    },
                    # Extra JSON fields for log querying
                    extra={
                        "service": self.service_log_id,
                        "query_type": hc_request["type"],
                        "user": self.user_id,
                        **extra,
                    },
                )

    def get_allowed_fields(self, query_type: str) -> list[str]:
        """Determine all values for the "fields" parameter that the user has access to.

        This value is used when no default is given.

        :param query_type: The "zoekvraag/doelbinding" (the "type" parameter in the request).
        """
        allowed_by_scope = self.parameter_ruleset["fields"].get_allowed_values(self.user_scopes)
        allowed_by_type = self.possible_fields_by_type.get(query_type, None)

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
