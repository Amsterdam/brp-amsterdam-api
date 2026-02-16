import re
from collections import defaultdict
from functools import reduce

from django.conf import settings
from django.http import HttpResponse, JsonResponse
from rest_framework.exceptions import APIException
from zeep import Client, Transport
from zeep.plugins import HistoryPlugin

from .base import BaseBrpClient
from .utils import derive_initials

BRP_CATEGORY_MAPPING = {
    "burgerservicenummer": "05.01.20",
    "geslacht": "05.04.10",
    "soortVerbintenis": "05.15.10",
    "naam.voornamen": "05.02.10",
    "naam.adellijkeTitelPredicaat": "05.02.20",
    "naam.voorvoegsel": "05.02.30",
    "naam.geslachtsnaam": "05.02.40",
    "naam.voorletters": {
        "source": "naam.voornamen",
        "function": derive_initials,
    },
    "geboorte.datum": "05.03.10",
    "geboorte.land": "05.03.20",
    "geboorte.plaats": "05.03.30",
    "aangaanHuwelijkParnerschap.datum": "05.06.10",
    "aangaanHuwelijkParnerschap.land": "05.06.20",
    "aangaanHuwelijkParnerschap.plaats": "05.06.30",
    "ontbindingHuwelijkParnerschap.datum": "05.07.10",
    "ontbindingHuwelijkParnerschap.land": "05.07.20",
    "ontbindingHuwelijkParnerschap.plaats": "05.07.30",
    "ontbindingHuwelijkParnerschap.reden": "05.07.40",
}

ADDITIONAL_FIELDS_FOR_DERIVATION = {
    "extra.inOnderzoek": "05.83.10",
    "extra.datumIngangOnderzoek": "05.83.20",
    "extra.datumEindeOnderzoek": "05.83.30",
}

CATEGORY_FIELD_MAPPING = {}


class BrpVAdhocServiceClient(BaseBrpClient):
    """
    BRP V Adhoc Service Client for connection to the ad-hoc BRP service to request partner history
    since this (currently) isn't part of the RvIG BRP APIs.
    """

    def __init__(
        self,
        endpoint_url,
        *,
        user: str | None = None,
        password: str | None = None,
        cert_file=None,
        key_file=None,
    ):
        super().__init__(endpoint_url, cert_file=cert_file, key_file=key_file)

        # Add basic auth to the session
        self._session.auth = (user, password)

        # Import the WSDL locally to bypass http import in the online file
        wsdl = f"{settings.SRC_DIR}/brp_amsterdam_api/bevragingen/clients/lrd_plus.wsdl"

        # For debugging purposes
        self.history = HistoryPlugin()

        transport = Transport(session=self._session)
        self.client = Client(wsdl=wsdl, transport=transport, plugins=[self.history])
        self.factory = self.client.type_factory("ns0")

    def call(self, hc_request: dict | None = None) -> HttpResponse | APIException:
        burgerservicenummer = hc_request["burgerservicenummer"]

        # Prepare request for the BRP Ad Hoc Service
        response = self.client.service.vraag(self._get_soap_request(burgerservicenummer))
        transformed_response = self._transform_response(response)

        return JsonResponse(transformed_response)

    def _get_soap_request(self, burgerservicenummer: str):
        return self.factory.Vraag(
            indicatieAdresvraag=0,
            indicatieZoekenInHistorie=0,
            masker=[{"item": _get_category_masks()}],
            parameters=[
                {
                    "item": [
                        {
                            "zoekwaarde": burgerservicenummer,
                            "rubrieknummer": 10120,
                        }
                    ]
                }
            ],
        )

    def _transform_response(self, response) -> dict:
        """
        Transform the response from the BRP-V Ad Hoc service to a JSON response.
        """
        partner_history = []
        for persoonslijst in response.persoonslijsten.item:
            partner = {}
            for categoriestapel in persoonslijst.categoriestapels.item:
                for categorievoorkomen in categoriestapel.categorievoorkomens.item:
                    category = categorievoorkomen.categorienummer
                    for item in categorievoorkomen.elementen.item:
                        group, element = re.findall("..", f"{item.nummer:04}")
                        if fields := _get_fields_by_category(
                            int(category), int(group), int(element)
                        ):
                            partner[fields[0]] = item.waarde
            partner_history.append(_group_dotted_result(partner))

        for p in partner_history:
            _derive_values(p)

            # Add the fields which are under investigation
            _derive_under_investigation(p)

        return {"partnerhistorie": partner_history}


def _derive_values(data: dict):
    """
    Edits the data in place with derived values
    """
    derived_fields = _get_derived_fields_mapping()
    for field, mapping in derived_fields.items():
        if source_value := _get_dotted_field_value(data, mapping["source"]):
            derived_value = mapping["function"](source_value)
            _set_dotted_field_value(data, field, derived_value)


def _derive_under_investigation(data: dict):
    """
    Edits the data in-place with the boolean flags

    We only get one value which determines if the whole category is under investigation, a group
    or an element. For example:

    - 050000 -> The whole category partner is under investigation
    - 050200 -> The group name under category is under investigation
    - 050610 -> The element aangaanHuwelijkParnerschap.datum is under investigation

    The result will be that the boolean flags on all elements match this logic
    """
    if source_value := _get_dotted_field_value(data, "extra.inOnderzoek"):
        category, group, element = (
            source_value[i : i + 2] for i in range(0, len(source_value), 2)
        )
        fields = _get_fields_by_category(int(category), int(group), int(element))

        for field in fields:
            if field.startswith("extra"):
                continue
            *base, leaf = field.split(".")
            if base:
                under_investigation_field_name = ".".join([*base, "inOnderzoek", leaf])
            else:
                under_investigation_field_name = f"inOnderzoek.{leaf}"

            _set_dotted_field_value(data, under_investigation_field_name, True)


def _get_categories() -> list:
    return [cat for cat in BRP_CATEGORY_MAPPING.values() if isinstance(cat, str)]


def _get_category_masks() -> list:
    """
    Returns all needed categories defined in the mapping formatted as integers
    """
    categories = _get_categories() + list(ADDITIONAL_FIELDS_FOR_DERIVATION.values())
    return [int(cat.replace(".", "")) for cat in categories]


def _get_category_field_mapping() -> dict:
    """
    Returns a dictionary by category, group and element number
    """
    categories = defaultdict(lambda: defaultdict(dict))
    for field, number in BRP_CATEGORY_MAPPING.items():
        # Skip deducted variables, since these are not in the response of the Ad Hoc Service
        if isinstance(number, dict):
            continue
        category, group, element = number.split(".")
        categories[int(category)][int(group)][int(element)] = field
    return categories


def _get_fields_by_category(category: int, group: int, element: int) -> list:
    category_mapping = _get_category_field_mapping()

    try:
        if element:
            return [category_mapping.get(category, {}).get(group, {})[element]]
        if group:
            return list(category_mapping.get(category, {})[group].values())

        fields = []
        for _, value in category_mapping[category].items():
            fields += list(value.values())
        return fields
    except KeyError:
        return []


def _get_derived_fields_mapping() -> dict:
    """
    Returns a dictionary for all derived fields
    """
    return {k: v for k, v in BRP_CATEGORY_MAPPING.items() if isinstance(v, dict)}


def _get_dotted_field_value(data, field) -> str | None:
    try:
        return reduce(dict.get, field.split("."), data)
    except TypeError:
        return None


def _group_dotted_result(dotted_result) -> dict:
    result = {}
    for dotted_name, value in dotted_result.items():
        tree_level = result
        *keys, leaf = dotted_name.split(".")
        for k in keys:
            tree_level = tree_level.setdefault(k, {})
        print(leaf)
        tree_level[leaf] = value
    return result


def _set_dotted_field_value(data, dotted_field, value):
    """
    Adds the value on the dotted path to the data in-place
    """
    tree_level = data
    *keys, leaf = dotted_field.split(".")
    for k in keys:
        if k not in tree_level:
            tree_level = tree_level.setdefault(k, {})
            continue
        tree_level = tree_level[k]
    tree_level[leaf] = value
