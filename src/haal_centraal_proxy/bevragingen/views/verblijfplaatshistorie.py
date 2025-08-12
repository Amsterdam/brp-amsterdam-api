from django.conf import settings

from haal_centraal_proxy.bevragingen import fields, types
from haal_centraal_proxy.bevragingen.permissions import ParameterPolicy

from .base import BaseHealthCheckView, BaseProxyView, DictOfDicts, group_dotted_names

BASE_FIELD_NAMES = fields.read_config("haal_centraal/verblijfplaatshistorie/fields.csv")
ADRES_FIELD_NAMES = fields.read_config("haal_centraal/verblijfplaatshistorie/fields-Adres.csv")
LOCATIE_FIELD_NAMES = fields.read_config("haal_centraal/verblijfplaatshistorie/fields-Locatie.csv")
VERBLIJFPLAATSBUITENLAND_FIELD_NAMES = fields.read_config(
    "haal_centraal/verblijfplaatshistorie/fields-VerblijfplaatsBuitenland.csv"
)
VERBLIJFPLAATSONBEKEND_FIELD_NAMES = fields.read_config(
    "haal_centraal/verblijfplaatshistorie/fields-VerblijfplaatsOnbekend.csv"
)

FIELD_NAMES_TYPE_MAPPING = {
    "Adres": ADRES_FIELD_NAMES,
    "Locatie": LOCATIE_FIELD_NAMES,
    "VerblijfplaatsBuitenland": VERBLIJFPLAATSBUITENLAND_FIELD_NAMES,
    "VerblijfplaatsOnbekend": VERBLIJFPLAATSONBEKEND_FIELD_NAMES,
}


class BrpVerblijfplaatshistorieHealthView(BaseHealthCheckView):
    """View to check backend access."""

    throttle_scope = "verblijfplaatshistorie:health"
    endpoint_url = settings.BRP_VERBLIJFPLAATSHISTORIE_URL


class BrpVerblijfplaatshistorieView(BaseProxyView):
    """View that proxies Haal Centraal BRP Verblijfplaatshistorie of a person (residence history).

    See: https://brp-api.github.io/Haal-Centraal-BRP-historie-bevragen/
    """

    service_log_id = "verblijfplaatshistorie"
    endpoint_url = settings.BRP_VERBLIJFPLAATSHISTORIE_URL

    # Require extra scopes
    needed_scopes = {"benk-brp-verblijfplaatshistorie-api"}

    # A quick dictionary to automate permission-based access to certain filter parameters.
    parameter_ruleset = {
        "type": ParameterPolicy(
            scopes_for_values={
                "RaadpleegMetPeildatum": {"benk-brp-verblijfplaatshistorie-api"},
                "RaadpleegMetPeriode": {"benk-brp-verblijfplaatshistorie-api"},
            }
        ),
        "burgerservicenummer": ParameterPolicy.allow_all,  # used for both request types.
        "peildatum": ParameterPolicy.allow_all,  # for RaadpleegMetPeildatum
        "datumTot": ParameterPolicy.allow_all,  # for RaadpleegMetPeriode
        "datumVan": ParameterPolicy.allow_all,  # for RaadpleegMetPeriode
    }

    top_level_array_fields = []

    def _insert_null_values(
        self, hc_request: types.PersonenQuery, hc_response: types.PersonenResponse
    ) -> None:
        """Insert any null values that the user does have access to.
        This allows the client to distinguish between having 'no value' instead of 'no access'.
        """
        request_fields = group_dotted_names(BASE_FIELD_NAMES)
        self._include_nulls(request_fields, hc_response)

    def _include_nulls(self, request_fields: DictOfDicts, item: list | dict, parent_path=()):
        """Include null values based on the collection of requested fields"""
        if isinstance(item, list):
            for sub_item in item:
                self._include_nulls(request_fields, sub_item, parent_path=parent_path)
        elif isinstance(item, dict):
            if "type" in item:
                type_fields = group_dotted_names(FIELD_NAMES_TYPE_MAPPING[item["type"]])
                request_fields.update(type_fields)
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
