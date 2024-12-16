import orjson
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
            "/api/brp/bewoningen",
            "/api/brp/verblijfsplaatshistorie",
            "/api/reisdocumenten/reisdocumenten",
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

    def test_invalid_api_key(self, api_client, urllib3_mocker, caplog):
        """Prove that incorrect API-key settings are handled gracefully."""
        urllib3_mocker.add(
            "POST",
            "/haalcentraal/api/brp/personen",
            body=orjson.dumps(
                {
                    "type": "https://datatracker.ietf.org/doc/html/rfc7235#section-3.1",
                    "title": "Niet correct geauthenticeerd.",
                    "status": 401,
                    "instance": "/haalcentraal/api/brp/personen",
                    "code": "authentication",
                }
            ),
            status=401,
            content_type="application/json",
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
        assert response.status_code == 403
        assert caplog.messages[1].startswith(
            "Granted access for personen.ZoekMetPostcodeEnHuisnummer, needed:"
        ), caplog.messages
        assert response.json() == {
            "type": "https://datatracker.ietf.org/doc/html/rfc7231#section-6.5.3",
            "title": "You do not have permission to perform this action.",
            "status": 403,
            "detail": "401 from remote: Niet correct geauthenticeerd.",
            "code": "permission_denied",
            "instance": "/api/brp/personen",
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

    def test_bsn_search(self, api_client, urllib3_mocker):
        """Prove that search is possible"""
        urllib3_mocker.add(
            "POST",
            "/haalcentraal/api/brp/personen",
            body=orjson.dumps(self.RESPONSE_POSTCODE_HUISNUMMER),
            content_type="application/json",
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
        assert response.json() == self.RESPONSE_POSTCODE_HUISNUMMER

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

        assert hc_request == {
            "type": "RaadpleegMetBurgerservicenummer",
            "fields": ["naam.aanduidingNaamgebruik"],
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

        assert hc_request == {
            "type": "RaadpleegMetBurgerservicenummer",
            "fields": ["naam.aanduidingNaamgebruik"],
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
                # not: pad
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
    def test_hide_confidential(self, api_client, urllib3_mocker, hide):
        """Prove that confidential persons are hidden."""
        person1 = {
            "naam": {"geslachtsnaam": "FOO"},
        }
        person2 = {
            "naam": {"geslachtsnaam": "BAR"},
            "geheimhoudingPersoonsgegevens": "1",
        }
        urllib3_mocker.add(
            "POST",
            "/haalcentraal/api/brp/personen",
            body=orjson.dumps(
                {
                    "type": "ZoekMetPostcodeEnHuisnummer",
                    "personen": [person1, person2],
                }
            ),
            content_type="application/json",
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

    def test_address_id_search(self, api_client, urllib3_mocker):
        """Prove that search is possible"""
        urllib3_mocker.add(
            "POST",
            # https://demo-omgeving.haalcentraal.nl
            "/haalcentraal/api/bewoning/bewoningen",
            body=orjson.dumps(self.RESPONSE_BEWONINGEN),
            content_type="application/json",
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
        assert response.json() == self.RESPONSE_BEWONINGEN

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

    def test_bsn_date_search(self, api_client, urllib3_mocker):
        """Prove that search is possible"""
        urllib3_mocker.add(
            "POST",
            # https://demo-omgeving.haalcentraal.nl
            "/haalcentraal/api/brphistorie/verblijfplaatshistorie",
            body=orjson.dumps(self.RESPONSE_VERBLIJFSPLAATS),
            content_type="application/json",
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
        assert response.json() == self.RESPONSE_VERBLIJFSPLAATS

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


class TestReisdocumentenView:
    """Prove that the API works as advertised."""

    RESPONSE_REISDOCUMENTEN = {
        "type": "ZoekMetBurgerservicenummer",
        "reisdocumenten": [
            {
                "reisdocumentnummer": "NW21K79D5",
                "soort": {"code": "PN", "omschrijving": "Nationaal paspoort"},
                "datumEindeGeldigheid": {
                    "type": "Datum",
                    "datum": "2030-12-03",
                    "langFormaat": "3 december 2030",
                },
                "houder": {"burgerservicenummer": "999993240"},
            }
        ],
    }

    def test_bsn_search(self, api_client, urllib3_mocker):
        """Prove that search is possible"""
        urllib3_mocker.add(
            "POST",
            # https://proefomgeving.haalcentraal.nl
            "/haalcentraal/api/reisdocumenten/reisdocumenten",
            body=orjson.dumps(self.RESPONSE_REISDOCUMENTEN),
            content_type="application/json",
        )

        url = reverse("reisdocumenten")
        token = build_jwt_token(["benk-brp-api", "BRP/zoek-doc-bsn", "BRP/x"])
        response = api_client.post(
            url,
            {
                "type": "ZoekMetBurgerservicenummer",
                "burgerservicenummer": "999993240",
                "fields": [
                    "reisdocumentnummer",
                    "soort",
                    "houder",
                    "datumEindeGeldigheid",
                    "inhoudingOfVermissing",
                ],
            },
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
        assert response.status_code == 200, response.data
        assert response.json() == self.RESPONSE_REISDOCUMENTEN

    def test_bsn_search__deny(self, api_client):
        """Prove that acess is checked"""
        url = reverse("reisdocumenten")
        token = build_jwt_token(["benk-brp-api"])
        response = api_client.post(
            url,
            {
                "type": "ZoekMetBurgerservicenummer",
                "burgerservicenummer": "999993240",
                "fields": [
                    "reisdocumentnummer",
                    "soort",
                    "houder",
                    "datumEindeGeldigheid",
                    "inhoudingOfVermissing",
                ],
            },
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )
        assert response.status_code == 403, response.data
        assert response.data["code"] == "permissionDenied"
