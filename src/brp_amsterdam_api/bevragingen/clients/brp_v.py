import logging
import re
from collections import defaultdict
from functools import reduce

from django.conf import settings
from django.http import HttpResponse, JsonResponse
from rest_framework.exceptions import APIException
from zeep import Client, Transport
from zeep.plugins import HistoryPlugin

from brp_amsterdam_api.bevragingen.exceptions import BadGateway

from .base import BaseBrpClient
from .utils import derive_date, derive_description, derive_initials

logger = logging.getLogger(__name__)

BRP_CATEGORY_MAPPING = {
    "burgerservicenummer": "05.01.20",
    "geslacht.code": "05.04.10",
    "geslacht.omschrijving": {
        "source": "geslacht.code",
        "function": derive_description,
        "args": "GENDER_CODE_TABLE",
    },
    "naam.voornamen": "05.02.10",
    "naam.adellijkeTitelPredicaat": "05.02.20",
    "naam.voorvoegsel": "05.02.30",
    "naam.geslachtsnaam": "05.02.40",
    "naam.voorletters": {
        "source": "naam.voornamen",
        "function": derive_initials,
    },
    "geboorte.datum": "05.03.10",
    "geboorte.plaats.code": "05.03.20",
    "geboorte.plaats.omschrijving": {
        "source": "geboorte.plaats.code",
        "function": derive_description,
        "args": "CITY_CODE_TABLE",
    },
    "geboorte.land.code": "05.03.30",
    "geboorte.land.omschrijving": {
        "source": "geboorte.land.code",
        "function": derive_description,
        "args": "COUNTRY_CODE_TABLE",
    },
    "aangaanHuwelijkPartnerschap.datum": "05.06.10",
    "aangaanHuwelijkPartnerschap.plaats.code": "05.06.20",
    "aangaanHuwelijkPartnerschap.plaats.omschrijving": {
        "source": "aangaanHuwelijkPartnerschap.plaats.code",
        "function": derive_description,
        "args": "CITY_CODE_TABLE",
    },
    "aangaanHuwelijkPartnerschap.land.code": "05.06.30",
    "aangaanHuwelijkPartnerschap.land.omschrijving": {
        "source": "aangaanHuwelijkPartnerschap.land.code",
        "function": derive_description,
        "args": "COUNTRY_CODE_TABLE",
    },
    "ontbindingHuwelijkPartnerschap.datum": "05.07.10",
    "ontbindingHuwelijkPartnerschap.plaats.code": "05.07.20",
    "ontbindingHuwelijkPartnerschap.plaats.omschrijving": {
        "source": "ontbindingHuwelijkPartnerschap.plaats.code",
        "function": derive_description,
        "args": "CITY_CODE_TABLE",
    },
    "ontbindingHuwelijkPartnerschap.land.code": "05.07.30",
    "ontbindingHuwelijkPartnerschap.land.omschrijving": {
        "source": "ontbindingHuwelijkPartnerschap.land.code",
        "function": derive_description,
        "args": "COUNTRY_CODE_TABLE",
    },
    "ontbindingHuwelijkPartnerschap.reden.code": "05.07.40",
    "ontbindingHuwelijkPartnerschap.reden.omschrijving": {
        "source": "ontbindingHuwelijkPartnerschap.reden.code",
        "function": derive_description,
        "args": "REASON_DISSOLUTION_TABLE",
    },
}

ADDITIONAL_FIELDS_FOR_RELATION_START = {
    "extra.aangaanHuwelijkPartnerschap.datum": "55.06.10",
    "extra.aangaanHuwelijkPartnerschap.plaats.code": "55.06.20",
    "extra.aangaanHuwelijkPartnerschap.land.code": "55.06.30",
}

ADDITIONAL_FIELDS_FOR_UNDER_INVESTIGATION = {
    "extra.inOnderzoek": "05.83.10",
    "extra.datumIngangOnderzoek": "05.83.20",
    "extra.datumEindeOnderzoek": "05.83.30",
}


class PasswordNotChanged(Exception):
    pass


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
        if settings.ENVIRONMENT == "prd":
            wsdl = f"{settings.SRC_DIR}/brp_amsterdam_api/bevragingen/clients/prd_lrd_plus.wsdl"
        else:
            wsdl = f"{settings.SRC_DIR}/brp_amsterdam_api/bevragingen/clients/lrd_plus.wsdl"

        # For debugging purposes
        self.history = HistoryPlugin()

        transport = Transport(session=self._session)
        self.client = Client(wsdl=wsdl, transport=transport, plugins=[self.history])
        self.factory = self.client.type_factory("ns0")

    def call(self, hc_request: dict | None = None) -> HttpResponse | APIException:
        burgerservicenummer = hc_request["burgerservicenummer"]
        requested_fields = hc_request["fields"]

        # Prepare request for the BRP Ad Hoc Service
        response = self.client.service.vraag(
            self._get_soap_request(burgerservicenummer, requested_fields)
        )

        # Log an error if we get an unexpected error from the BRP Ad Hoc Service
        if response.resultaat.letter == "X":
            logger.error(
                "Proxy call failed, unexpected error X%s: %s",
                response.resultaat.code,
                response.resultaat.omschrijving,
            )
            raise BadGateway("Unexpected error from BRP Ad Hoc Service")

        transformed_response = self._transform_response(response, requested_fields)

        return JsonResponse(transformed_response)

    def change_password(self, password: str) -> None:
        """
        Change the password for the BRP V Ad Hoc Service. This is needed every 90 days.
        """
        response = self.client.service.changePassword(password)
        if response.code in [101, 110, 111, 112, 113, 114]:
            error_message = f"Code: {response.code} \nDetail: {response.omschrijving}"
            raise PasswordNotChanged(
                f"Failed to change password for BRP V Ad Hoc Service\n{error_message}"
            )

    def _get_soap_request(self, burgerservicenummer: str, fields: list[str]):
        return self.factory.Vraag(
            indicatieAdresvraag=0,
            indicatieZoekenInHistorie=1,
            masker=[{"item": _get_category_masks(fields)}],
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

    def _transform_response(self, response, requested_fields: list[str]) -> dict:
        """
        Transform the response from the BRP-V Ad Hoc service to a JSON response.
        """
        partner_history = []
        for persoonslijst in response.persoonslijsten.item:
            for categoriestapel in persoonslijst.categoriestapels.item:
                partner = {}
                for categorievoorkomen in categoriestapel.categorievoorkomens.item:
                    category = categorievoorkomen.categorienummer
                    # We're only interested in category 5/55 (partner)
                    if category not in [5, 55]:
                        break
                    for item in categorievoorkomen.elementen.item:
                        group, element = re.findall("..", f"{item.nummer:04}")
                        if fields := _get_fields_by_category(
                            int(category), int(group), int(element)
                        ):
                            partner[fields[0]] = item.waarde
                if partner:
                    partner_history.append(_group_dotted_result(partner))

        for p in partner_history:
            _transform_partner_data(p, requested_fields)

        return {"partnerhistorie": [_clean_empty_dicts(p) for p in partner_history]}


def _transform_partner_data(partner: dict, requested_fields: list[str]) -> dict:
    """
    Transforms the partner data from the BRP Ad Hoc Service to the desired format.

    This includes:
    - Deriving values based on other values (e.g. deriving the description of a code)
    - Deriving date fields to a standard format
    - Adding boolean flags for fields that are under investigation
    - Clean up the response by removing fields that are disallowed
    """
    _derive_relation_start(partner)

    _derive_values(partner)

    _derive_date_fields(partner)

    # Add the fields which are under investigation
    _derive_under_investigation(partner)

    # Remove the fields which are only used for derivation
    if "extra" in partner:
        del partner["extra"]

    # Remove any disallowed fields
    for field in BRP_CATEGORY_MAPPING:
        if field in requested_fields or any(field.startswith(f) for f in requested_fields):
            continue
        _remove_dotted_field(partner, field)


def _derive_relation_start(data: dict):
    # If the relation has been dissolved, the start date of the relation can be derived the extra
    # fields in category 55.
    extra_relation_fields = [
        field
        for field in ADDITIONAL_FIELDS_FOR_RELATION_START
        if field.startswith("extra.aangaanHuwelijkPartnerschap")
    ]

    for field in extra_relation_fields:
        if source_value := _get_dotted_field_value(data, field):
            relation_start_field = field.replace("extra.", "")
            _set_dotted_field_value(data, relation_start_field, source_value)


def _derive_values(data: dict):
    """
    Edits the data in place with derived values
    """
    derived_fields = _get_derived_fields_mapping()
    for field, mapping in derived_fields.items():
        if source_value := _get_dotted_field_value(data, mapping["source"]):
            args = [source_value]
            if "args" in mapping:
                args += mapping["args"] if isinstance(mapping["args"], list) else [mapping["args"]]
            derived_value = mapping["function"](*args)
            _set_dotted_field_value(data, field, derived_value)


def _derive_date_fields(data: dict):
    date_fields = [field for field in BRP_CATEGORY_MAPPING if ".datum" in field]
    for field in date_fields:
        if current_value := _get_dotted_field_value(data, field):
            _set_dotted_field_value(data, field, derive_date(current_value))


def _derive_under_investigation(data: dict):
    """
    Edits the data in-place with the boolean flags

    We only get one value which determines if the whole category is under investigation, a group
    or an element. For example:

    - 050000 -> The whole category partner is under investigation
    - 050200 -> The group name under category is under investigation
    - 050610 -> The element aangaanHuwelijkPartnerschap.datum is under investigation

    The result will be that the boolean flags on all elements match this logic
    """
    if source_value := _get_dotted_field_value(data, "extra.inOnderzoek"):
        category, group, element = (
            source_value[i : i + 2] for i in range(0, len(source_value), 2)
        )
        fields = _get_fields_by_category(int(category), int(group), int(element))

        # Remove code/omschrijving from field names
        fields = {field.replace(".code", "").replace("omschrijving", "") for field in fields}

        for field in fields:
            if field.startswith("extra"):
                continue

            *base, leaf = field.split(".")
            if base:
                under_investigation_field_name = ".".join([*base, "inOnderzoek", leaf])
            else:
                under_investigation_field_name = f"inOnderzoek.{leaf}"

            _set_dotted_field_value(data, under_investigation_field_name, True)


def _get_category_masks(fields) -> list:
    """
    Returns all requested categories defined in the mapping formatted as integers
    """
    categories = []
    for field, cat in BRP_CATEGORY_MAPPING.items():
        if field not in fields and not any(field.startswith(f) for f in fields):
            continue

        if isinstance(cat, str):
            categories.append(cat)

        # If we are authorized to see the source field of a derived field, we also need to request
        # the category of the source field
        if isinstance(cat, dict):
            source_field = cat["source"]
            source_cat = BRP_CATEGORY_MAPPING[cat["source"]]
            if (
                source_field in fields or any(field.startswith(f) for f in fields)
            ) and source_cat not in categories:
                categories.append(source_cat)

    # Add the additional fields for derivation of relation start
    categories += [
        cat
        for field, cat in ADDITIONAL_FIELDS_FOR_RELATION_START.items()
        if field.replace("extra.", "") in fields
    ]

    # Add the additional fields for under investigation
    categories += [
        cat
        for field, cat in ADDITIONAL_FIELDS_FOR_UNDER_INVESTIGATION.items()
        if field.replace("extra.", "") in fields
    ]

    return [int(cat.replace(".", "")) for cat in categories]


def _get_category_field_mapping() -> dict:
    """
    Returns a dictionary by category, group and element number
    """
    categories = defaultdict(lambda: defaultdict(dict))

    all_fields = {
        **BRP_CATEGORY_MAPPING,
        **ADDITIONAL_FIELDS_FOR_RELATION_START,
        **ADDITIONAL_FIELDS_FOR_UNDER_INVESTIGATION,
    }

    for field, number in all_fields.items():
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


def _remove_dotted_field(data, dotted_field):
    """
    Removes the value on the dotted path from the data in-place
    """
    tree_level = data
    *keys, leaf = dotted_field.split(".")
    for k in keys:
        if k not in tree_level:
            return
        tree_level = tree_level[k]
    if leaf in tree_level:
        del tree_level[leaf]


def _clean_empty_dicts(data):
    """
    Cleans empty dicts from the data
    """
    if not isinstance(data, dict):
        return data
    return {key: v for key, value in data.items() if (v := _clean_empty_dicts(value)) != {}}
