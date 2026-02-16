import pytest

from brp_amsterdam_api.bevragingen.clients.brp_v import (
    _derive_under_investigation,
    _derive_values,
    _get_fields_by_category,
)


class TestBrpVAdhocServiceClient:

    def test_derive_values(self):
        data = {"naam": {"voornamen": "Jan-Willem Hendrikus"}}
        _derive_values(data)
        assert data["naam"]["voorletters"] == "J.H."

    @pytest.mark.parametrize(
        "value, expected",
        [
            (
                "050620",
                {
                    "extra": {"inOnderzoek": "050620"},
                    "aangaanHuwelijkParnerschap": {"inOnderzoek": {"land": True}},
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
