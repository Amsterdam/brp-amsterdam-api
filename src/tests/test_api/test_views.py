import pytest
from django.urls import reverse
from haal_centraal_proxy.api import views
from haal_centraal_proxy.api.fields import read_dataset_fields_files

from tests.utils import build_jwt_token


class TestBaseProxyView:
    """Prove that the generic view offers the login check logic.
    This is tested through the concrete implementations though.
    """

    @pytest.mark.parametrize(
        "url",
        [
            "/api/brp/personen",
            "/api/brp/bewoningen",
            "/api/brp/verblijfsplaatshistorie",
        ],
    )
    def test_no_login(self, api_client, url):
        """Prove that accessing the view fails without a login token."""
        response = api_client.post(url)
        assert response.status_code == 403
        assert response.data == {
            "type": "https://datatracker.ietf.org/doc/html/rfc7231#section-6.5.3",
            "code": "not_authenticated",
            "title": "Authentication credentials were not provided.",
            "detail": "",
            "status": 403,
            "instance": url,
        }

    def test_invalid_api_key(self, api_client, requests_mock, caplog):
        """Prove that incorrect API-key settings are handled gracefully."""
        requests_mock.post(
            "/haalcentraal/api/brp/personen",
            json={
                "type": "https://datatracker.ietf.org/doc/html/rfc7235#section-3.1",
                "title": "Niet correct geauthenticeerd.",
                "status": 401,
                "instance": "/haalcentraal/api/brp/personen",
                "code": "authentication",
            },
            status_code=401,
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
        assert response.status_code == 502
        assert any(
            m.startswith("Access granted for 'personen.ZoekMetPostcodeEnHuisnummer' to '")
            for m in caplog.messages
        ), caplog.messages
        assert response.json() == {
            "type": "https://datatracker.ietf.org/doc/html/rfc7231#section-6.6.3",
            "title": "Connection failed (bad gateway)",
            "status": 502,
            "detail": "Backend is improperly configured, final endpoint rejected our credentials.",
            "code": "backend_config",
            "instance": "/api/brp/personen",
        }

    def test_error_response(self, api_client, requests_mock, caplog):
        requests_mock.post(
            "/haalcentraal/api/brp/personen",
            json={
                "invalidParams": [
                    {
                        "name": "burgerservicenummer",
                        "code": "array",
                        "reason": "Parameter is geen array.",
                    }
                ],
                "type": "https://datatracker.ietf.org/doc/html/rfc7231#section-6.5.1",
                "title": "Een of meerdere parameters zijn niet correct.",
                "status": 400,
                "detail": "De foutieve parameter(s) zijn: burgerservicenummer.",
                "instance": "/haalcentraal/api/brp/personen",
                "code": "paramsValidation",
            },
            status_code=400,
            headers={"content-type": "application/json"},
        )

        url = reverse("brp-personen")
        token = build_jwt_token(
            ["benk-brp-api", "benk-brp-zoekvraag-bsn", "benk-brp-gegevensset-1"]
        )
        response = api_client.post(
            url,
            {"type": "RaadpleegMetBurgerservicenummer", "burgerservicenummer": "000009830"},
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
        assert response.status_code == 400
        assert any(
            m.startswith("Access granted for 'personen.RaadpleegMetBurgerservicenummer' to '")
            for m in caplog.messages
        ), caplog.messages
        assert response.json() == {
            "code": "paramsValidation",
            "detail": "De foutieve parameter(s) zijn: burgerservicenummer.",
            "instance": "/api/brp/personen",
            "invalidParams": [
                {
                    "code": "array",
                    "name": "burgerservicenummer",
                    "reason": "Parameter is geen array.",
                }
            ],
            "status": 400,
            "title": "Een of meerdere parameters zijn niet correct.",
            "type": "https://datatracker.ietf.org/doc/html/rfc7231#section-6.5.1",
        }


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
        view = views.BrpPersonenView()
        view.user_scopes = {
            "benk-brp-zoekvraag-bsn",
            "benk-brp-gegevensset-1",
            views.SCOPE_NATIONWIDE,
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
        view = views.BrpPersonenView()
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

        view = views.BrpPersonenView()
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
        view = views.BrpPersonenView()
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
            scopes.append(views.SCOPE_ALLOW_CONFIDENTIAL_PERSONS)
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
                views.BrpPersonenView.parameter_ruleset,
                "fields",
                views.ParameterPolicy(
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


class TestBrpBewoningenView:
    """Prove that the API works as advertised."""

    RESPONSE_BEWONINGEN = {
        "bewoningen": [
            {
                "adresseerbaarObjectIdentificatie": "0518010000832200",
                "periode": {"datumVan": "2020-09-24", "datumTot": "2020-09-25"},
                "bewoners": [{"burgerservicenummer": "999993240"}],
                "mogelijkeBewoners": [],
            }
        ]
    }

    def test_address_id_search(self, api_client, requests_mock):
        """Prove that search is possible"""
        requests_mock.post(
            # https://demo-omgeving.haalcentraal.nl
            "/haalcentraal/api/bewoning/bewoningen",
            json=self.RESPONSE_BEWONINGEN,
            headers={"content-type": "application/json"},
        )

        url = reverse("brp-bewoningen")
        token = build_jwt_token(["benk-brp-api", "BRP/zoek-bewoningen"])
        response = api_client.post(
            url,
            {
                "type": "BewoningMetPeildatum",
                "adresseerbaarObjectIdentificatie": "0518010000832200",
                "peildatum": "2020-09-24",
            },
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
        assert response.status_code == 200, response
        assert response.json() == self.RESPONSE_BEWONINGEN, response.data

    def test_address_id_search_deny(self, api_client):
        """Prove that acess is checked"""
        url = reverse("brp-bewoningen")
        token = build_jwt_token(["benk-brp-api"])

        response = api_client.post(
            url,
            {
                "type": "BewoningMetPeildatum",
                "adresseerbaarObjectIdentificatie": "0518010000832200",
                "peildatum": "2020-09-24",
            },
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
        assert response.status_code == 403, response.data
        assert response.data["code"] == "permissionDenied"


class BrpVerblijfsplaatsHistorieView:
    """Prove that the API works as advertised."""

    RESPONSE_VERBLIJFSPLAATS = {
        "verblijfplaatsen": [
            {
                "type": "Adres",
                "verblijfadres": {
                    "officieleStraatnaam": "Erasmusweg",
                    "korteStraatnaam": "Erasmusweg",
                    "huisnummer": 471,
                    "postcode": "2532CN",
                    "woonplaats": "'s-Gravenhage",
                },
                "functieAdres": {"code": "W", "omschrijving": "woonadres"},
                "adresseerbaarObjectIdentificatie": "0518010000832200",
                "nummeraanduidingIdentificatie": "0518200000832199",
                "gemeenteVanInschrijving": {"code": "0518", "omschrijving": "'s-Gravenhage"},
                "datumVan": {
                    "type": "Datum",
                    "datum": "1990-04-27",
                    "langFormaat": "27 april 1990",
                },
                "adressering": {
                    "adresregel1": "Erasmusweg 471",
                    "adresregel2": "2532 CN  'S-GRAVENHAGE",
                },
            }
        ]
    }

    def test_bsn_date_search(self, api_client, requests_mock):
        """Prove that search is possible"""
        requests_mock.post(
            # https://demo-omgeving.haalcentraal.nl
            "/haalcentraal/api/brphistorie/verblijfplaatshistorie",
            json=self.RESPONSE_VERBLIJFSPLAATS,
            headers={"content-type": "application/json"},
        )

        url = reverse("brp-verblijfsplaatshistorie")
        token = build_jwt_token(["benk-brp-api", "BRP/zoek-historie"])
        response = api_client.post(
            url,
            {
                "type": "RaadpleegMetPeildatum",
                "burgerservicenummer": "999993240",
                "peildatum": "2020-09-24",
            },
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
        assert response.status_code == 200, response
        assert response.json() == self.RESPONSE_VERBLIJFSPLAATS, response.data

    def test_bsn_date_search_deny(self, api_client):
        """Prove that acess is checked"""
        url = reverse("brp-verblijfsplaatshistorie")
        token = build_jwt_token(["benk-brp-api"])
        response = api_client.post(
            url,
            {
                "type": "RaadpleegMetPeildatum",
                "burgerservicenummer": "999993240",
                "peildatum": "2020-09-24",
            },
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
        assert response.status_code == 403, response.data
        assert response.data["code"] == "permissionDenied"
