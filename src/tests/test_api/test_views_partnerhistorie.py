from django.urls import reverse

from brp_amsterdam_api.bevragingen.views import BrpPartnerhistorieView
from brp_amsterdam_api.bevragingen.views.partnerhistorie import DISALLOWED_FIELDS
from tests.utils import build_jwt_token


class TestBrpPartnerhistorieView:
    """Prove that the BRP view works as advertised.

    This includes tests that are specific for the BRP (not generic tests).
    """

    def test_partnerhistorie_view(self, api_client, requests_mock, common_headers):
        """Prove a search is possible and that the response is properly parsed and
        transformed to the expected output."""
        with open("tests/data/response-simple.xml") as mock_response:

            requests_mock.post("/gba-v/online/lo3services/adhoc", text=mock_response.read())

            url = reverse("brp-partnerhistorie")
            token = build_jwt_token(
                [
                    "benk-brp-personen-api",
                    "benk-brp-partnerhistorie-api",
                    "benk-brp-gegevensset-20",
                ]
            )
            response = api_client.post(
                url,
                {"type": "RaadpleegMetBurgerservicenummer", "burgerservicenummer": "123456789"},
                headers={
                    "Authorization": f"Bearer {token}",
                    **common_headers,
                },
            )
            assert response.status_code == 200, response.data
            assert response.json() == {
                "partnerhistorie": [
                    {
                        "aangaanHuwelijkPartnerschap": {
                            "datum": {
                                "datum": "2014-12-01",
                                "langFormaat": "1 december 2014",
                                "type": "Datum",
                            },
                        },
                        "naam": {
                            "geslachtsnaam": "Arendsen",
                            "voorletters": "A.",
                        },
                    }
                ]
            }

    def test_partnerhistorie_error_response(self, api_client, requests_mock, common_headers):
        """Prove an error response is properly handled and logged."""
        with open("tests/data/response-error.xml") as mock_response:

            requests_mock.post("/gba-v/online/lo3services/adhoc", text=mock_response.read())

            url = reverse("brp-partnerhistorie")
            token = build_jwt_token(
                [
                    "benk-brp-personen-api",
                    "benk-brp-partnerhistorie-api",
                    "benk-brp-gegevensset-20",
                ]
            )
            response = api_client.post(
                url,
                {"type": "RaadpleegMetBurgerservicenummer", "burgerservicenummer": "123456789"},
                headers={
                    "Authorization": f"Bearer {token}",
                    **common_headers,
                },
            )
            assert response.status_code == 502, response.data
            assert response.json() == {
                "code": "badGateway",
                "detail": "Unexpected error from BRP Ad Hoc Service",
                "instance": "/bevragingen/v1/partnerhistorie",
                "status": 502,
                "title": "Connection failed (bad gateway)",
                "type": "https://datatracker.ietf.org/doc/html/rfc7231#section-6.6.3",
            }

    def test_partnerhistorie_disallow_fields(self, api_client, requests_mock, common_headers):
        """Prove a search is denied if fields are requested without proper permissions"""
        url = reverse("brp-partnerhistorie")
        token = build_jwt_token(
            [
                "benk-brp-personen-api",
                "benk-brp-partnerhistorie-api",
                "benk-brp-gegevensset-20",
            ]
        )
        response = api_client.post(
            url,
            {
                "type": "RaadpleegMetBurgerservicenummer",
                "burgerservicenummer": "123456789",
                "fields": ["burgerservicenummer"],
            },
            headers={
                "Authorization": f"Bearer {token}",
                **common_headers,
            },
        )
        assert response.status_code == 403, response.data
        assert response.json() == {
            "code": "permissionDenied",
            "detail": "U bent niet geautoriseerd voor fields = burgerservicenummer.",
            "instance": "/bevragingen/v1/partnerhistorie",
            "invalidParams": [{"code": "denied", "name": "fields", "reason": "Geen toegang."}],
            "status": 403,
            "title": "U bent niet geautoriseerd voor deze operatie.",
            "type": "https://datatracker.ietf.org/doc/html/rfc7231#section-6.5.3",
        }

    def test_partnerhistorie_view_null_values(self, api_client, requests_mock, common_headers):
        """Prove that the 'resultaat-formaat=volledig' query parameter results in null values
        for missing fields instead of omitting them."""
        with open("tests/data/response-simple.xml") as mock_response:
            requests_mock.post("/gba-v/online/lo3services/adhoc", text=mock_response.read())

            url = reverse("brp-partnerhistorie")
            token = build_jwt_token(
                [
                    "benk-brp-personen-api",
                    "benk-brp-partnerhistorie-api",
                    "benk-brp-gegevensset-22",
                ]
            )
            response = api_client.post(
                f"{url}?resultaat-formaat=volledig",
                {"type": "RaadpleegMetBurgerservicenummer", "burgerservicenummer": "123456789"},
                headers={
                    "Authorization": f"Bearer {token}",
                    **common_headers,
                },
            )
            assert response.status_code == 200, response.data
            assert response.json() == {
                "partnerhistorie": [
                    {
                        "aangaanHuwelijkPartnerschap": {
                            "datum": {
                                "datum": "2014-12-01",
                                "langFormaat": "1 december 2014",
                                "type": "Datum",
                            },
                        },
                        "burgerservicenummer": "999998791",
                        "geboorte": {
                            "datum": {
                                "datum": "1981-01-01",
                                "langFormaat": "1 januari 1981",
                                "type": "Datum",
                            },
                        },
                        "naam": {
                            "adellijkeTitelPredicaat": None,
                            "geslachtsnaam": "Arendsen",
                            "voorletters": "A.",
                            "voornamen": "Adam",
                            "voorvoegsel": None,
                        },
                        "ontbindingHuwelijkPartnerschap": {
                            "datum": None,
                        },
                    }
                ]
            }

    def test_partnerhistorie_historical_relationships(
        self, api_client, requests_mock, common_headers
    ):
        """Prove that historical relationships are derived from category 55 if it exists."""
        with open("tests/data/response-historical-relationships.xml") as mock_response:
            requests_mock.post("/gba-v/online/lo3services/adhoc", text=mock_response.read())

            url = reverse("brp-partnerhistorie")
            token = build_jwt_token(
                [
                    "benk-brp-personen-api",
                    "benk-brp-partnerhistorie-api",
                    "benk-brp-gegevensset-22",
                ]
            )
            response = api_client.post(
                f"{url}",
                {"type": "RaadpleegMetBurgerservicenummer", "burgerservicenummer": "123456789"},
                headers={
                    "Authorization": f"Bearer {token}",
                    **common_headers,
                },
            )
            assert response.status_code == 200, response.data
            assert response.json() == {
                "partnerhistorie": [
                    {
                        "aangaanHuwelijkPartnerschap": {
                            "datum": {
                                "datum": "2008-08-01",
                                "langFormaat": "1 augustus 2008",
                                "type": "Datum",
                            },
                        },
                        "burgerservicenummer": "999991747",
                        "geboorte": {
                            "datum": {
                                "datum": "1990-03-31",
                                "langFormaat": "31 maart 1990",
                                "type": "Datum",
                            },
                        },
                        "naam": {
                            "geslachtsnaam": "Bilgiç",
                            "voorletters": "A.",
                            "voornamen": "Ayse",
                        },
                    },
                    {
                        "aangaanHuwelijkPartnerschap": {
                            "datum": {
                                "datum": "2001-07-30",
                                "langFormaat": "30 juli 2001",
                                "type": "Datum",
                            },
                        },
                        "burgerservicenummer": "999992958",
                        "geboorte": {
                            "datum": {
                                "datum": "1969-12-15",
                                "langFormaat": "15 december 1969",
                                "type": "Datum",
                            },
                        },
                        "naam": {
                            "geslachtsnaam": "Buren",
                            "voorletters": "A.",
                            "voornamen": "Anita",
                            "voorvoegsel": "van",
                        },
                        "ontbindingHuwelijkPartnerschap": {
                            "datum": {
                                "datum": "2003-09-21",
                                "langFormaat": "21 september 2003",
                                "type": "Datum",
                            },
                        },
                    },
                ],
            }

    def test_partnerhistorie_other_categories_ignored(
        self, api_client, requests_mock, common_headers
    ):
        """Prove that possible other categories in the response are ignored."""
        with open("tests/data/response-other-category.xml") as mock_response:
            requests_mock.post("/gba-v/online/lo3services/adhoc", text=mock_response.read())

            url = reverse("brp-partnerhistorie")
            token = build_jwt_token(
                [
                    "benk-brp-personen-api",
                    "benk-brp-partnerhistorie-api",
                    "benk-brp-gegevensset-22",
                ]
            )
            response = api_client.post(
                f"{url}",
                {"type": "RaadpleegMetBurgerservicenummer", "burgerservicenummer": "123456789"},
                headers={
                    "Authorization": f"Bearer {token}",
                    **common_headers,
                },
            )
            assert response.status_code == 200, response.data
            assert response.json() == {
                "partnerhistorie": [
                    {
                        "burgerservicenummer": "999998912",
                        "geboorte": {
                            "datum": {
                                "datum": "1982-04-01",
                                "langFormaat": "1 april 1982",
                                "type": "Datum",
                            },
                        },
                        "naam": {
                            "geslachtsnaam": "Krabben",
                            "voorletters": "K.",
                            "voornamen": "Koosje",
                            "voorvoegsel": "van",
                        },
                        "aangaanHuwelijkPartnerschap": {
                            "datum": {
                                "datum": "2019-04-01",
                                "langFormaat": "1 april 2019",
                                "type": "Datum",
                            },
                        },
                    },
                ],
            }

    def test_partnerhistorie_bsns_logger(self, api_client, requests_mock, caplog, common_headers):
        """Prove that bsns from both the request and response are logged."""
        with open("tests/data/response-other-category.xml") as mock_response:
            requests_mock.post("/gba-v/online/lo3services/adhoc", text=mock_response.read())

            url = reverse("brp-partnerhistorie")
            token = build_jwt_token(
                [
                    "benk-brp-personen-api",
                    "benk-brp-partnerhistorie-api",
                    "benk-brp-gegevensset-22",
                ]
            )
            response = api_client.post(
                f"{url}",
                {"type": "RaadpleegMetBurgerservicenummer", "burgerservicenummer": "123456789"},
                headers={
                    "Authorization": f"Bearer {token}",
                    **common_headers,
                },
            )
            assert response.status_code == 200, response.data
            assert response.json() == {
                "partnerhistorie": [
                    {
                        "burgerservicenummer": "999998912",
                        "geboorte": {
                            "datum": {
                                "datum": "1982-04-01",
                                "langFormaat": "1 april 1982",
                                "type": "Datum",
                            },
                        },
                        "naam": {
                            "geslachtsnaam": "Krabben",
                            "voorletters": "K.",
                            "voornamen": "Koosje",
                            "voorvoegsel": "van",
                        },
                        "aangaanHuwelijkPartnerschap": {
                            "datum": {
                                "datum": "2019-04-01",
                                "langFormaat": "1 april 2019",
                                "type": "Datum",
                            },
                        },
                    },
                ],
            }

            log_records = caplog.records
            log = next(
                (record for record in log_records if record.message.startswith("Access")),
                None,
            )
            assert log is not None
            assert all(bsn in log.burgerservicenummers for bsn in ["123456789", "999998912"])
            assert log.aNummers == []

            # Log message should contain the full request/response context
            assert all(getattr(log, attr) for attr in ["request", "hcRequest", "hcResponse"])

    def test_transform_includes_bsn(self):
        """Prove that BSN is added to the request for logging purposes even if the user has no
        permissions for this field.
        """
        view = BrpPartnerhistorieView()
        view.user_scopes = {
            "benk-brp-partnerhistorie-api",
            "benk-brp-gegevensset-20",
        }
        hc_request = {
            "type": "RaadpleegMetBurgerservicenummer",
            "burgerservicenummer": "123456789",
            "fields": ["aangaanHuwelijkPartnerschap"],
        }
        view.transform_request(hc_request)
        assert view.inserted_id_fields == ["burgerservicenummer"]

        assert hc_request == {
            "type": "RaadpleegMetBurgerservicenummer",
            "burgerservicenummer": "123456789",
            "fields": ["aangaanHuwelijkPartnerschap", "burgerservicenummer"],
        }

    def test_disallowed_fields_not_requested(self):
        """Prove that disallowed fields are not requested in the partnerhistorie endpoint.
        Gegevensset-18 includes aangaanHuwelijkPartnerschap.plaats and
        aangaanHuwelijkPartnerschap.land
        """
        view = BrpPartnerhistorieView()
        view.user_scopes = {
            "benk-brp-partnerhistorie-api",
            "benk-brp-gegevensset-18",
        }
        hc_request = {
            "type": "RaadpleegMetBurgerservicenummer",
            "burgerservicenummer": "123456789",
        }
        view.transform_request(hc_request)
        assert all(field not in hc_request["fields"] for field in DISALLOWED_FIELDS)
