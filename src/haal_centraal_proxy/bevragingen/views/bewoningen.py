from django.conf import settings
from rest_framework.exceptions import APIException

from haal_centraal_proxy.bevragingen import types
from haal_centraal_proxy.bevragingen.permissions import ParameterPolicy

from .base import BaseHealthCheckView, BaseProxyView, audit_log


class BrpBewoningenHealthView(BaseHealthCheckView):
    """View to check backend access."""

    permission_classes = []
    throttle_scope = "bewoningen:health"
    endpoint_url = settings.BRP_BEWONINGEN_URL


class BrpBewoningenView(BaseProxyView):
    """View to proxy Haal Centraal Bewoning (ocupancy).

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
        super().log_access_granted(
            request, hc_request, hc_response, final_response, needed_scopes, exception
        )

        if exception is None:
            # Separate log message for every person that's being accessed.
            personen = []
            for bewoning in hc_response["bewoningen"]:
                personen += bewoning.get("bewoners", []) + bewoning.get("mogelijkeBewoners", [])
            for persoon in personen:
                msg_params = {}
                extra = {
                    "request": request.data,
                    "hc_request": hc_request,
                    "hc_response": final_response or hc_response,
                }
                msg = ["User %(user)s retrieved using '%(service)s.%(query_type)s':"]
                msg_params["burgerservicenummer"] = persoon.get("burgerservicenummer", "?")
                extra["burgerservicenummer"] = persoon.get("burgerservicenummer", None)
                msg.append("burgerservicenummer=%(burgerservicenummer)s")

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
                        **self.default_log_fields,
                        **extra,
                    },
                )
