from django.conf import settings
from rest_framework.request import Request

from brp_amsterdam_api.bevragingen.clients.brp_v import BrpVAdhocServiceClient
from brp_amsterdam_api.bevragingen.permissions import ParameterPolicy

from .base import BaseProxyView


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
