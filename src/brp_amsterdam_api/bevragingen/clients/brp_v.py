from collections import defaultdict

from django.conf import settings
from django.http import HttpResponse, JsonResponse
from rest_framework.exceptions import APIException
from zeep import Client, Transport
from zeep.plugins import HistoryPlugin

from .base import BaseBrpClient

BRP_CATEGORY_MAPPING = {
    "burgerservicenummer": "05.0120",
    "geslacht": "05.0410",
    "soortVerbintenis": "05.1510",
    "naam.voornamen": "05.0210",
    "naam.adellijkeTitelPredicaat": "05.0220",
    "naam.voorvoegsel": "05.0230",
    "naam.geslachtsnaam": "05.0240",
    "naam.voorletters": {
        "source": "naam.voornamen",
        "function": "deduct_initials",
    },
    "naam.inOnderzoek": "05.8310",
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
        field_mapping = _get_category_field_mapping()
        partner_history = []
        for persoonslijst in response.persoonslijsten.item:
            partner = {}
            for categoriestapel in persoonslijst.categoriestapels.item:
                for categorievoorkomen in categoriestapel.categorievoorkomens.item:
                    if categorievoorkomen.categorienummer in field_mapping:
                        for element in categorievoorkomen.elementen.item:
                            category_mapping = field_mapping[categorievoorkomen.categorienummer]
                            if element.nummer in category_mapping:
                                partner[category_mapping[element.nummer]] = element.waarde
            partner_history.append(_group_dotted_result(partner))

        return {"partnerhistorie": partner_history}


def _get_categories() -> list:
    return [cat for cat in BRP_CATEGORY_MAPPING.values() if isinstance(cat, str)]


def _get_category_masks() -> list:
    """
    Returns all needed categories defined in the mapping formatted as integers
    """
    return [int(cat.replace(".", "")) for cat in _get_categories()]


def _get_category_field_mapping() -> dict:
    """
    Returns a dictionary by category and element number
    """
    categories = defaultdict(dict)
    for field, number in BRP_CATEGORY_MAPPING.items():
        print(field, number)
        if isinstance(number, dict):
            continue
        category, element = number.split(".")
        categories[int(category)][int(element)] = field
    return categories


def _group_dotted_result(dotted_result) -> dict:
    result = {}
    for dotted_name, value in dotted_result.items():
        tree_level = result
        *keys, leaf = dotted_name.split(".")
        for k in keys:
            tree_level = tree_level.setdefault(k, {})
        tree_level[leaf] = value
    return result
