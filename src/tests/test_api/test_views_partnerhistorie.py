from django.urls import reverse

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
                            "land": {"code": "6030", "omschrijving": "Nederland"},
                            "plaats": {"code": "0518", "omschrijving": "'s-Gravenhage"},
                        },
                        "burgerservicenummer": "999998791",
                        "geboorte": {
                            "datum": {
                                "datum": "1981-01-01",
                                "langFormaat": "1 januari 1981",
                                "type": "Datum",
                            },
                            "land": {"code": "6030", "omschrijving": "Nederland"},
                            "plaats": {"code": "0518", "omschrijving": "'s-Gravenhage"},
                        },
                        "geslacht": {"code": "M", "omschrijving": "man"},
                        "naam": {
                            "geslachtsnaam": "Arendsen",
                            "voorletters": "A.",
                            "voornamen": "Adam",
                        },
                        "soortVerbintenis": {"code": "H", "omschrijving": "huwelijk"},
                    }
                ]
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
                            "land": {"code": "6030", "omschrijving": "Nederland"},
                            "plaats": {"code": "0518", "omschrijving": "'s-Gravenhage"},
                        },
                        "burgerservicenummer": "999998791",
                        "geboorte": {
                            "datum": {
                                "datum": "1981-01-01",
                                "langFormaat": "1 januari 1981",
                                "type": "Datum",
                            },
                            "land": {"code": "6030", "omschrijving": "Nederland"},
                            "plaats": {"code": "0518", "omschrijving": "'s-Gravenhage"},
                        },
                        "geslacht": {"code": "M", "omschrijving": "man"},
                        "naam": {
                            "adellijkeTitelPredicaat": None,
                            "geslachtsnaam": "Arendsen",
                            "voorletters": "A.",
                            "voornamen": "Adam",
                            "voorvoegsel": None,
                        },
                        "soortVerbintenis": {"code": "H", "omschrijving": "huwelijk"},
                        "ontbindingHuwelijkPartnerschap": {
                            "datum": None,
                            "land": {
                                "code": None,
                                "omschrijving": None,
                            },
                            "plaats": {
                                "code": None,
                                "omschrijving": None,
                            },
                            "reden": {
                                "code": None,
                                "omschrijving": None,
                            },
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
                            "land": {
                                "code": "6030",
                                "omschrijving": "Nederland",
                            },
                            "plaats": {
                                "code": "0363",
                                "omschrijving": "Amsterdam",
                            },
                        },
                        "burgerservicenummer": "999991747",
                        "geboorte": {
                            "datum": {
                                "datum": "1990-03-31",
                                "langFormaat": "31 maart 1990",
                                "type": "Datum",
                            },
                            "land": {
                                "code": "6045",
                                "omschrijving": "Joegoslavië",
                            },
                            "plaats": {
                                "code": "Belgrado",
                                "omschrijving": "Belgrado",
                            },
                        },
                        "geslacht": {
                            "code": "V",
                            "omschrijving": "vrouw",
                        },
                        "naam": {
                            "geslachtsnaam": "Bilgiç",
                            "voorletters": "A.",
                            "voornamen": "Ayse",
                        },
                        "soortVerbintenis": {
                            "code": "H",
                            "omschrijving": "huwelijk",
                        },
                    },
                    {
                        "aangaanHuwelijkPartnerschap": {
                            "datum": {
                                "datum": "2001-07-30",
                                "langFormaat": "30 juli 2001",
                                "type": "Datum",
                            },
                            "plaats": {
                                "code": "0363",
                                "omschrijving": "Amsterdam",
                            },
                            "land": {
                                "code": "6030",
                                "omschrijving": "Nederland",
                            },
                        },
                        "burgerservicenummer": "999992958",
                        "geboorte": {
                            "datum": {
                                "datum": "1969-12-15",
                                "langFormaat": "15 december 1969",
                                "type": "Datum",
                            },
                            "land": {
                                "code": "6030",
                                "omschrijving": "Nederland",
                            },
                            "plaats": {
                                "code": "0294",
                                "omschrijving": "Winterswijk",
                            },
                        },
                        "geslacht": {
                            "code": "V",
                            "omschrijving": "vrouw",
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
                            "land": {
                                "code": "6030",
                                "omschrijving": "Nederland",
                            },
                            "plaats": {
                                "code": "0363",
                                "omschrijving": "Amsterdam",
                            },
                            "reden": {
                                "code": "S",
                                "omschrijving": "echtsch of huw.ontb na sch van tfl en "
                                "bed/eindigen partnersch door ovk of ontb",
                            },
                        },
                        "soortVerbintenis": {
                            "code": "H",
                            "omschrijving": "huwelijk",
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
                            "land": {
                                "code": "6030",
                                "omschrijving": "Nederland",
                            },
                            "plaats": {
                                "code": "0518",
                                "omschrijving": "'s-Gravenhage",
                            },
                        },
                        "geslacht": {
                            "code": "V",
                            "omschrijving": "vrouw",
                        },
                        "naam": {
                            "geslachtsnaam": "Krabben",
                            "voorletters": "K.",
                            "voornamen": "Koosje",
                            "voorvoegsel": "van",
                        },
                        "soortVerbintenis": {
                            "code": "P",
                            "omschrijving": "geregistreerd partnerschap",
                        },
                        "aangaanHuwelijkPartnerschap": {
                            "datum": {
                                "datum": "2019-04-01",
                                "langFormaat": "1 april 2019",
                                "type": "Datum",
                            },
                            "land": {
                                "code": "6030",
                                "omschrijving": "Nederland",
                            },
                            "plaats": {
                                "code": "0518",
                                "omschrijving": "'s-Gravenhage",
                            },
                        },
                    },
                ],
            }
