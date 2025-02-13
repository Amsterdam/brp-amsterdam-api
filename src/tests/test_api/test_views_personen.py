import pytest
from django.urls import reverse
from haal_centraal_proxy.api.fields import read_dataset_fields_files
from haal_centraal_proxy.api.permissions import ParameterPolicy
from haal_centraal_proxy.api.views.personen import (
    SCOPE_ALLOW_CONFIDENTIAL_PERSONS,
    SCOPE_NATIONWIDE,
    BrpPersonenView,
)

from tests.utils import build_jwt_token


class TestBrpPersonenView:
    """Prove that the BRP view works as advertised.

    This incluedes tests that are specific for the BRP (not generic tests).
    """

    RESPONSE_POSTCODE_HUISNUMMER = {
        "type": "ZoekMetPostcodeEnHuisnummer",
        "personen": [
            {
                "naam": {
                    "voornamen": "Ronald Franciscus Maria",
                    "geslachtsnaam": "Moes",
                    "voorletters": "R.F.M.",
                    "volledigeNaam": "Ronald Franciscus Maria Moes",
                    "aanduidingNaamgebruik": {
                        "code": "E",
                        "omschrijving": "eigen geslachtsnaam",
                    },
                }
            }
        ],
    }

    def test_bsn_search(self, api_client, requests_mock):
        """Prove that search is possible"""
        requests_mock.post(
            "/haalcentraal/api/brp/personen",
            json=self.RESPONSE_POSTCODE_HUISNUMMER,
            headers={"content-type": "application/json"},
        )

        url = reverse("brp-personen")
        token = build_jwt_token(
            ["benk-brp-api", "benk-brp-zoekvraag-postcode-huisnummer", "benk-brp-gegevensset-1"]
        )
        response = api_client.post(
            url,
            {
                "type": "ZoekMetPostcodeEnHuisnummer",
                "postcode": "1074VE",
                "huisnummer": 1,
                "fields": ["naam.aanduidingNaamgebruik"],
            },
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
        assert response.status_code == 200, response.data
        assert response.json() == self.RESPONSE_POSTCODE_HUISNUMMER, response.data

    def test_bsn_search_deny(self, api_client):
        """Prove that search is possible"""
        url = reverse("brp-personen")
        token = build_jwt_token(["benk-brp-api"])

        response = api_client.post(
            url,
            {
                "type": "ZoekMetPostcodeEnHuisnummer",
                "postcode": "1074VE",
                "huisnummer": 1,
                "fields": ["naam"],
            },
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
        assert response.status_code == 403, response.data
        assert response.data["code"] == "permissionDenied"

    def test_defaults_allow_nationwide(self):
        """Prove that 'gemeenteVanInschrijving' won't be added if there is nationwide access."""
        view = BrpPersonenView()
        view.user_scopes = {
            "benk-brp-zoekvraag-bsn",
            "benk-brp-gegevensset-1",
            SCOPE_NATIONWIDE,
        }
        hc_request = {
            "type": "RaadpleegMetBurgerservicenummer",
            "fields": ["naam.aanduidingNaamgebruik"],
        }
        view.transform_request(hc_request)
        assert view.inserted_id_fields == ["aNummer", "burgerservicenummer"]

        assert hc_request == {
            "type": "RaadpleegMetBurgerservicenummer",
            # Note that the 'fields' are also updated for logging purposes
            "fields": ["naam.aanduidingNaamgebruik", "aNummer", "burgerservicenummer"],
            # no gemeenteVanInschrijving added.
        }

    def test_defaults_enforce_municipality(self):
        """Prove that 'gemeenteVanInschrijving' will be added."""
        view = BrpPersonenView()
        view.user_scopes = {"benk-brp-zoekvraag-bsn", "benk-brp-gegevensset-1"}
        hc_request = {
            "type": "RaadpleegMetBurgerservicenummer",
            "fields": ["naam.aanduidingNaamgebruik"],
        }
        view.transform_request(hc_request)
        assert view.inserted_id_fields == ["aNummer", "burgerservicenummer"]

        assert hc_request == {
            "type": "RaadpleegMetBurgerservicenummer",
            # Note that the 'fields' are also updated for logging purposes
            "fields": ["naam.aanduidingNaamgebruik", "aNummer", "burgerservicenummer"],  # added
            "gemeenteVanInschrijving": "0363",  # added (missing scope to seek outside area)
        }

    def test_defaults_add_fields(self):
        """Prove that 'fields' and 'gemeente-filter is added."""
        set1 = sorted(
            read_dataset_fields_files("dataset_fields/personen/benk-brp-gegevensset-1.txt").keys()
        )

        view = BrpPersonenView()
        view.user_scopes = {"benk-brp-zoekvraag-bsn", "benk-brp-gegevensset-1"}
        hc_request = {
            "type": "RaadpleegMetBurgerservicenummer",
        }

        view.transform_request(hc_request)
        hc_request["fields"].sort()

        assert hc_request == {
            "type": "RaadpleegMetBurgerservicenummer",
            "gemeenteVanInschrijving": "0363",  # added (missing scope to seek outside area)
            "fields": set1,  # added (default all allowed fields)
        }

    def test_defaults_add_fields_limited(self):
        """Prove that 'fields' and 'gemeente-filter is added."""
        view = BrpPersonenView()
        view.user_scopes = {"benk-brp-zoekvraag-postcode-huisnummer", "benk-brp-gegevensset-1"}
        hc_request = {
            "type": "ZoekMetPostcodeEnHuisnummer",
        }

        view.transform_request(hc_request)
        hc_request["fields"].sort()

        assert hc_request == {
            "type": "ZoekMetPostcodeEnHuisnummer",
            "gemeenteVanInschrijving": "0363",  # added (missing scope to seek outside area)
            "fields": [
                # added (very limited set due to constraints of both the fields CSV and scope)
                "adressering.adresregel1",
                "adressering.adresregel2",
                "adressering.adresregel3",
                "adressering.land",
                "burgerservicenummer",
                "geboorte.datum",
                "geslacht",
                "leeftijd",
                "naam.adellijkeTitelPredicaat",
                "naam.geslachtsnaam",
                "naam.volledigeNaam",
                "naam.voorletters",
                "naam.voornamen",
                "naam.voorvoegsel",
                # not: adresseringBinnenland.adresregel1
                # not: adresseringBinnenland.adresregel2
            ],
        }

    def test_defaults_missing_sets(self, api_client):
        """Prove that not having access to a set is handled gracefully."""
        url = reverse("brp-personen")
        token = build_jwt_token(
            ["benk-brp-api", "benk-brp-zoekvraag-bsn", "benk-brp-gegevensset-foobar"]
        )

        response = api_client.post(
            url,
            {"type": "RaadpleegMetBurgerservicenummer"},
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
        assert response.status_code == 403, response.data
        assert response.data["code"] == "permissionDenied"
        assert response.data["detail"] == (
            "U bent niet geautoriseerd voor een gegevensset bij deze operatie."
        )

    @pytest.mark.parametrize("hide", [True, False])
    def test_hide_confidential(self, api_client, requests_mock, hide, caplog):
        """Prove that confidential persons are hidden."""
        person1 = {
            "naam": {"geslachtsnaam": "FOO"},
        }
        person2 = {
            "naam": {"geslachtsnaam": "BAR"},
            "geheimhoudingPersoonsgegevens": "1",
        }
        requests_mock.post(
            "/haalcentraal/api/brp/personen",
            json={
                "type": "ZoekMetPostcodeEnHuisnummer",
                "personen": [person1, person2],
            },
            headers={"content-type": "application/json"},
        )
        url = reverse("brp-personen")
        scopes = [
            "benk-brp-api",
            "benk-brp-zoekvraag-postcode-huisnummer",
            "benk-brp-gegevensset-1",
        ]
        if not hide:
            scopes.append(SCOPE_ALLOW_CONFIDENTIAL_PERSONS)
        response = api_client.post(
            url,
            {
                "type": "ZoekMetPostcodeEnHuisnummer",
                "postcode": "1074VE",
                "huisnummer": 1,
                "fields": ["naam.geslachtsnaam"],
            },
            HTTP_AUTHORIZATION=f"Bearer {build_jwt_token(scopes)}",
        )
        assert response.status_code == 200, response.data
        personen = response.json()["personen"]
        expect = [person1] if hide else [person1, person2]
        assert personen == expect

        if hide:
            assert any(
                m.startswith("Removed 1 persons from response") for m in caplog.messages
            ), caplog.messages

    @pytest.mark.parametrize("can_see_bsn", [True, False])
    def test_log_retrieved_bsns(self, api_client, requests_mock, caplog, monkeypatch, can_see_bsn):
        """Prove that retrieved BSNs are always logged.

        Even when the user doesn't have access to that field, or won't request it,
        the field will still be included in the logs - but not returned in the response.
        """
        if not can_see_bsn:
            monkeypatch.setitem(
                BrpPersonenView.parameter_ruleset,
                "fields",
                ParameterPolicy(
                    scopes_for_values={"naam.geslachtsnaam": {"unittest-gegevensset-1"}},
                    default_scope=None,
                ),
            )

        requests_mock.post(
            "/haalcentraal/api/brp/personen",
            json={
                "type": "ZoekMetPostcodeEnHuisnummer",
                "personen": [
                    {
                        "naam": {"geslachtsnaam": "DUMMY_REMOVED1"},
                        "burgerservicenummer": "999993240",
                    },
                    {
                        "naam": {"geslachtsnaam": "DUMMY_REMOVED2"},
                        "burgerservicenummer": "999993252",
                    },
                ],
            },
            headers={"content-type": "application/json"},
        )

        url = reverse("brp-personen")
        scopes = [
            "benk-brp-api",
            "benk-brp-zoekvraag-postcode-huisnummer",
            ("unittest-gegevensset-1" if not can_see_bsn else "benk-brp-gegevensset-1"),
        ]
        response = api_client.post(
            url,
            {
                "type": "ZoekMetPostcodeEnHuisnummer",
                "postcode": "1074VE",
                "huisnummer": 1,
                "fields": ["naam.geslachtsnaam"],
            },
            HTTP_AUTHORIZATION=f"Bearer {build_jwt_token(scopes)}",
        )
        assert response.status_code == 200, response.data
        response = response.json()

        assert response == {
            "type": "ZoekMetPostcodeEnHuisnummer",
            "personen": [
                # burgerservicenummer retrieved from endpoint, but stripped before sending response
                {
                    "naam": {"geslachtsnaam": "DUMMY_REMOVED1"},
                },
                {
                    "naam": {"geslachtsnaam": "DUMMY_REMOVED2"},
                },
            ],
        }
        log_messages = caplog.messages
        for log_message in [
            "User doesn't request ID field burgerservicenummer, only adding for internal logging",
            "Removing additional identifier fields from response: burgerservicenummer",
            (
                "User text@example.com retrieved using 'personen.ZoekMetPostcodeEnHuisnummer':"
                " aNummer=? burgerservicenummer=999993240"
            ),
            (
                "User text@example.com retrieved using 'personen.ZoekMetPostcodeEnHuisnummer':"
                " aNummer=? burgerservicenummer=999993252"
            ),
        ]:
            assert log_message in log_messages
