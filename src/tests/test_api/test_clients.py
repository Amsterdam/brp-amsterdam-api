import pytest

from brp_amsterdam_api.bevragingen.clients.brp_v import (
    _clean_empty_dicts,
    _derive_date_fields,
    _derive_under_investigation,
    _derive_values,
    _get_fields_by_category,
)


class TestBrpVAdhocServiceClient:

    def test_derive_initials(self):
        data = {"naam": {"voornamen": "Jan-Willem Hendrikus"}}
        _derive_values(data)
        assert data["naam"]["voorletters"] == "J.H."

    def test_derive_city(self):
        data = {"geboorte": {"plaats": {"code": "0363"}}}
        _derive_values(data)
        assert data["geboorte"]["plaats"]["omschrijving"] == "Amsterdam"

    def test_derive_country(self):
        data = {"geboorte": {"land": {"code": "6030"}}}
        _derive_values(data)
        assert data["geboorte"]["land"]["omschrijving"] == "Nederland"

    def test_derive_reason_dissolution(self):
        data = {"ontbindingHuwelijkPartnerschap": {"reden": {"code": "S"}}}
        _derive_values(data)
        assert (
            data["ontbindingHuwelijkPartnerschap"]["reden"]["omschrijving"]
            == "echtsch of huw.ontb na sch van tfl en bed/eindigen partnersch door ovk of ontb"
        )

    def test_derive_dates(self):
        data = {"geboorte": {"datum": "19700420"}}
        _derive_date_fields(data)
        assert data["geboorte"]["datum"] == {
            "datum": "1970-04-20",
            "type": "Datum",
            "langFormaat": "20 april 1970",
        }

    @pytest.mark.parametrize(
        "value, expected",
        [
            (
                "050620",
                {
                    "extra": {"inOnderzoek": "050620"},
                    "aangaanHuwelijkPartnerschap": {"inOnderzoek": {"plaats": True}},
                },
            ),
        ],
    )
    def test_derive_under_investigation(self, value, expected):
        data = {"extra": {"inOnderzoek": value}}
        _derive_under_investigation(data)
        assert data == expected

    def test_get_fields_by_category(self):
        assert _get_fields_by_category(5, 2, 10) == ["naam.voornamen"]
        assert _get_fields_by_category(5, 2, 0) == [
            "naam.voornamen",
            "naam.adellijkeTitelPredicaat",
            "naam.voorvoegsel",
            "naam.geslachtsnaam",
        ]
        assert _get_fields_by_category(7, 0, 0) == []

    def test_clean_empty_dicts(self):
        data = {
            "field1": {
                "subfield1": "value1",
                "subfield2": {},
                "subfield3": "",
                "subfield4": None,
            },
            "field2": {},
        }
        assert _clean_empty_dicts(data) == {
            "field1": {
                "subfield1": "value1",
                "subfield3": "",
                "subfield4": None,
            },
        }
