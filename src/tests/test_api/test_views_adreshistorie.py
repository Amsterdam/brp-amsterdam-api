from django.urls import reverse

from tests.utils import build_jwt_token


class TestBrpAdreshistorieView:
    """Prove that the BRP view works as advertised.

    This includes tests that are specific for the BRP (not generic tests).
    """

    def test_adreshistorie_view(self, api_client, requests_mock, common_headers):
        """Prove a search is possible and that the response is properly parsed and
        transformed to the expected output."""
        with open("tests/data/adreshistorie-response.xml") as mock_response:

            requests_mock.post("/gba-v/online/lo3services/adhoc", text=mock_response.read())

            url = reverse("brp-adreshistorie")
            token = build_jwt_token(
                [
                    "benk-brp-personen-api",
                    "benk-brp-adreshistorie-api",
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
                "adreshistorie": [
                    {
                        "gemeenteVanInschrijving": {
                            "code": "0518",
                            "omschrijving": "'s-Gravenhage",
                        },
                        "verblijfplaats": {
                            "functieAdres": {
                                "code": "W",
                                "omschrijving": "woonadres",
                            },
                            "datumVan": {
                                "type": "Datum",
                                "datum": "1970-04-01",
                                "langFormaat": "1 april 1970",
                            },
                            "verblijfadres": {
                                "korteStraatnaam": "Turfmarkt",
                                "officieleStraatnaam": "Turfmarkt",
                                "huisnummer": "15",
                                "postcode": "2511CA",
                                "woonplaats": "'s-Gravenhage",
                            },
                            "adresseerbaarObjectIdentificatie": "0518010000583536",
                            "nummeraanduidingIdentificatie": "0518200000583536",
                        },
                        "type": "Adres",
                    }
                ]
            }

    def test_adreshistorie_multiple_view(self, api_client, requests_mock, common_headers):
        """Prove a search is possible and that the response is properly parsed and
        transformed to the expected output."""
        with open("tests/data/adreshistorie-multiple.xml") as mock_response:

            requests_mock.post("/gba-v/online/lo3services/adhoc", text=mock_response.read())

            url = reverse("brp-adreshistorie")
            token = build_jwt_token(
                [
                    "benk-brp-personen-api",
                    "benk-brp-adreshistorie-api",
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
                "adreshistorie": [
                    {
                        "gemeenteVanInschrijving": {"code": "0363", "omschrijving": "Amsterdam"},
                        "verblijfplaats": {
                            "functieAdres": {"code": "W", "omschrijving": "woonadres"},
                            "datumVan": {
                                "type": "Datum",
                                "datum": "2024-07-31",
                                "langFormaat": "31 juli 2024",
                            },
                            "verblijfadres": {
                                "korteStraatnaam": "Laboratoriumstraat",
                                "officieleStraatnaam": "Laboratoriumstraat",
                                "huisnummer": "3",
                                "postcode": "1059BX",
                                "woonplaats": "Amsterdam",
                            },
                            "adresseerbaarObjectIdentificatie": "0363010000716965",
                            "nummeraanduidingIdentificatie": "0363200000177880",
                        },
                        "type": "Adres",
                    },
                    {
                        "gemeenteVanInschrijving": {
                            "code": "1999",
                            "omschrijving": "Registratie Niet Ingezetenen (RNI)",
                        },
                        "type": "VerblijfplaatsOnbekend",
                    },
                    {
                        "gemeenteVanInschrijving": {"code": "0363", "omschrijving": "Amsterdam"},
                        "verblijfplaats": {
                            "datumVan": {
                                "type": "Datum",
                                "datum": "2023-10-05",
                                "langFormaat": "5 oktober 2023",
                            },
                            "verblijfadres": {
                                "korteStraatnaam": "Laboratoriumstraat",
                                "officieleStraatnaam": "Laboratoriumstraat",
                                "huisnummer": "3",
                                "postcode": "1059BX",
                                "woonplaats": "Amsterdam",
                                "inOnderzoek": {
                                    "regel2": True,
                                    "huisletter": True,
                                    "huisnummer": True,
                                    "regel1": True,
                                    "locatiebeschrijving": True,
                                    "huisnummertoevoeging": True,
                                    "regel3": True,
                                    "woonplaats": True,
                                    "land": True,
                                    "korteStraatnaam": True,
                                    "postcode": True,
                                    "officieleStraatnaam": True,
                                    "datumIngangOnderzoek": {
                                        "type": "Datum",
                                        "datum": "2024-02-09",
                                        "langFormaat": "9 februari 2024",
                                    },
                                    "datumEindeOnderzoek": {
                                        "type": "Datum",
                                        "datum": "2024-05-20",
                                        "langFormaat": "20 mei 2024",
                                    },
                                },
                            },
                            "adresseerbaarObjectIdentificatie": "0363010000716965",
                            "nummeraanduidingIdentificatie": "0363200000177880",
                            "inOnderzoek": {
                                "functieAdres": True,
                                "nummeraanduidingIdentificatie": True,
                                "datumVan": True,
                                "adresseerbaarObjectIdentificatie": True,
                                "datumIngangOnderzoek": {
                                    "type": "Datum",
                                    "datum": "2024-02-09",
                                    "langFormaat": "9 februari 2024",
                                },
                                "datumEindeOnderzoek": {
                                    "type": "Datum",
                                    "datum": "2024-05-20",
                                    "langFormaat": "20 mei 2024",
                                },
                            },
                        },
                        "type": "Adres",
                        "datumInschrijvingInGemeente": {
                            "inOnderzoek": {
                                "datum": True,
                                "datumIngangOnderzoek": {
                                    "type": "Datum",
                                    "datum": "2024-02-09",
                                    "langFormaat": "9 februari 2024",
                                },
                                "datumEindeOnderzoek": {
                                    "type": "Datum",
                                    "datum": "2024-05-20",
                                    "langFormaat": "20 mei 2024",
                                },
                            }
                        },
                        "inOnderzoek": {"gemeenteVanInschrijving": True},
                    },
                    {
                        "gemeenteVanInschrijving": {
                            "code": "1999",
                            "omschrijving": "Registratie Niet Ingezetenen (RNI)",
                        },
                        "type": "VerblijfplaatsOnbekend",
                    },
                    {
                        "gemeenteVanInschrijving": {"code": "0363", "omschrijving": "Amsterdam"},
                        "verblijfplaats": {
                            "datumVan": {
                                "type": "Datum",
                                "datum": "2022-03-01",
                                "langFormaat": "1 maart 2022",
                            },
                            "verblijfadres": {
                                "korteStraatnaam": "Laboratoriumstraat",
                                "officieleStraatnaam": "Laboratoriumstraat",
                                "huisnummer": "3",
                                "postcode": "1059BX",
                                "woonplaats": "Amsterdam",
                                "inOnderzoek": {
                                    "regel2": True,
                                    "huisletter": True,
                                    "huisnummer": True,
                                    "regel1": True,
                                    "locatiebeschrijving": True,
                                    "huisnummertoevoeging": True,
                                    "regel3": True,
                                    "woonplaats": True,
                                    "land": True,
                                    "korteStraatnaam": True,
                                    "postcode": True,
                                    "officieleStraatnaam": True,
                                    "datumIngangOnderzoek": {
                                        "type": "Datum",
                                        "datum": "2023-05-19",
                                        "langFormaat": "19 mei 2023",
                                    },
                                    "datumEindeOnderzoek": {
                                        "type": "Datum",
                                        "datum": "2023-08-24",
                                        "langFormaat": "24 augustus 2023",
                                    },
                                },
                            },
                            "adresseerbaarObjectIdentificatie": "0363010000716965",
                            "nummeraanduidingIdentificatie": "0363200000177880",
                            "inOnderzoek": {
                                "functieAdres": True,
                                "nummeraanduidingIdentificatie": True,
                                "datumVan": True,
                                "adresseerbaarObjectIdentificatie": True,
                                "datumIngangOnderzoek": {
                                    "type": "Datum",
                                    "datum": "2023-05-19",
                                    "langFormaat": "19 mei 2023",
                                },
                                "datumEindeOnderzoek": {
                                    "type": "Datum",
                                    "datum": "2023-08-24",
                                    "langFormaat": "24 augustus 2023",
                                },
                            },
                        },
                        "type": "Adres",
                        "datumInschrijvingInGemeente": {
                            "inOnderzoek": {
                                "datum": True,
                                "datumIngangOnderzoek": {
                                    "type": "Datum",
                                    "datum": "2023-05-19",
                                    "langFormaat": "19 mei 2023",
                                },
                                "datumEindeOnderzoek": {
                                    "type": "Datum",
                                    "datum": "2023-08-24",
                                    "langFormaat": "24 augustus 2023",
                                },
                            }
                        },
                        "inOnderzoek": {"gemeenteVanInschrijving": True},
                    },
                ]
            }
