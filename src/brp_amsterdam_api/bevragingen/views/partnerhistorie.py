from django.conf import settings
from rest_framework.request import Request

from brp_amsterdam_api.bevragingen import types
from brp_amsterdam_api.bevragingen.clients.brp_v import (
    BRP_CATEGORY_MAPPING,
    BrpVAdhocServiceClient,
)
from brp_amsterdam_api.bevragingen.permissions import ParameterPolicy

from .base import BaseProxyView, group_dotted_names


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
        "burgerservicenummer": ParameterPolicy.allow_all,  # used for both request types.
    }

    top_level_array_fields = []

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

    def _insert_null_values(
        self, hc_request: types.PartnerhistorieQuery, hc_response: types.PartnerhistorieResponse
    ) -> None:
        """Insert any null values that the user does have access to.
        This allows the client to distinguish between having 'no value' instead of 'no access'.
        """
        print("HALLLO")
        request_fields = group_dotted_names(BRP_CATEGORY_MAPPING.keys())
        self._include_nulls(request_fields, hc_response["partnerhistorie"])
