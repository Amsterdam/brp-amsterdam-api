from django.conf import settings
from rest_framework.exceptions import APIException

from brp_amsterdam_api.bevragingen import fields, types
from brp_amsterdam_api.bevragingen.permissions import ParameterPolicy

from .base import BaseHealthCheckView, BaseProxyView, group_dotted_names

ALL_FIELD_NAMES = fields.read_config("rvig_brp_api/bewoningen/fields.csv")


class BrpBewoningenHealthView(BaseHealthCheckView):
    """View to check backend access."""

    permission_classes = []
    throttle_scope = "bewoningen:health"
    endpoint_url = settings.BRP_BEWONINGEN_URL


class BrpBewoningenView(BaseProxyView):
    """View to proxy RvIG BRP API Bewoning (ocupancy).

    See: https://brp-api.github.io/Haal-Centraal-BRP-bewoning/
    """

    service_log_id = "bewoningen"
    endpoint_url = settings.BRP_BEWONINGEN_URL

    # Require extra scopes
    needed_scopes = {"benk-brp-bewoning-api"}

    # Validate the access to various parameters:
    parameter_ruleset = {
        "type": ParameterPolicy(
            scopes_for_values={
                "BewoningMetPeildatum": {"benk-brp-bewoning-api"},
                "BewoningMetPeriode": {"benk-brp-bewoning-api"},
            }
        ),
        "adresseerbaarObjectIdentificatie": ParameterPolicy.allow_all,  # used for both types.
        "peildatum": ParameterPolicy.allow_all,  # for BewoningMetPeildatum
        "datumTot": ParameterPolicy.allow_all,  # for BewoningMetPeriode
        "datumVan": ParameterPolicy.allow_all,  # for BewoningMetPeriode
    }

    top_level_array_fields = [
        # Hard-coded list here of all array fields (which shouldn't get null-defaults).
        # This is based on the output of the get-openapi.py script.
        "bewoningen",
    ]

    def log_access_granted(
        self,
        request,
        hc_request: types.BaseQuery,
        hc_response: types.BewoningenResponse | None,
        final_response: types.BewoningenResponse | None,
        needed_scopes: set[str],
        exception: OSError | APIException | None = None,
    ) -> None:
        """Extend logging to also include each BSN that was returned in the response"""

        if exception is None:
            # Create an array of BSNs for every person that's being accessed.
            personen = []
            for bewoning in hc_response["bewoningen"]:
                personen += bewoning.get("bewoners", []) + bewoning.get("mogelijkeBewoners", [])
            bsns = []
            for persoon in personen:
                bsn = persoon.get("burgerservicenummer", "?")
                if bsn not in bsns:
                    bsns.append(bsn)

            super().log_access_granted(
                request,
                hc_request,
                hc_response,
                final_response,
                needed_scopes,
                exception,
                extra_params={"burgerservicenummers": bsns},
            )
            return

        super().log_access_granted(
            request, hc_request, hc_response, final_response, needed_scopes, exception
        )

    def _insert_null_values(
        self, hc_request: types.BaseQuery, hc_response: types.BaseResponse
    ) -> None:
        """Insert any null values that the user does have access to.
        This allows the client to distinguish between having 'no value' instead of 'no access'.
        """
        request_fields = group_dotted_names(ALL_FIELD_NAMES)
        self._include_nulls(request_fields, hc_response)
