from django.urls import reverse

from brp_amsterdam_api.bevragingen import encryption
from brp_amsterdam_api.bevragingen.views.base import SCOPE_ENCRYPT_BSN
from tests.utils import build_jwt_token


class TestBrpVerblijfplaatshistorieView:
    """Prove that the API works as advertised."""

    RESPONSE_VERBLIJFPLAATS = {
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
            },
            {
                "type": "Locatie",
                "verblijfadres": {
                    "officieleStraatnaam": "Erasmusweg",
                    "korteStraatnaam": "Erasmusweg",
                    "huisnummer": 471,
                    "postcode": "2532CN",
                    "woonplaats": "'s-Gravenhage",
                },
                "functieAdres": {"code": "W", "omschrijving": "woonadres"},
                "nummeraanduidingIdentificatie": "0518200000832199",
                "gemeenteVanInschrijving": {"code": "0518", "omschrijving": "'s-Gravenhage"},
                "adressering": {
                    "adresregel1": "Erasmusweg 471",
                    "adresregel2": "2532 CN  'S-GRAVENHAGE",
                },
            },
        ]
    }

    def test_bsn_date_search(self, api_client, requests_mock, common_headers):
        """Prove that search is possible"""
        requests_mock.post(
            "/lap/api/brp/verblijfplaatshistorie",
            json=self.RESPONSE_VERBLIJFPLAATS,
            headers={"content-type": "application/json"},
        )

        url = reverse("brp-verblijfplaatshistorie")
        token = build_jwt_token(["benk-brp-verblijfplaatshistorie-api"])
        response = api_client.post(
            url,
            {
                "type": "RaadpleegMetPeildatum",
                "burgerservicenummer": "999993240",
                "peildatum": "2020-09-24",
            },
            headers={
                "Authorization": f"Bearer {token}",
                **common_headers,
            },
        )
        assert response.status_code == 200, response
        assert response.json() == self.RESPONSE_VERBLIJFPLAATS, response.data

    def test_bsn_date_search_deny(self, api_client, common_headers):
        """Prove that access is checked"""
        url = reverse("brp-verblijfplaatshistorie")
        token = build_jwt_token(["benk-brp-SOME-OTHER-api"])
        response = api_client.post(
            url,
            {
                "type": "RaadpleegMetPeildatum",
                "burgerservicenummer": "999993240",
                "peildatum": "2020-09-24",
            },
            headers={
                "Authorization": f"Bearer {token}",
                **common_headers,
            },
        )
        assert response.status_code == 403, response.data
        assert response.data["code"] == "permissionDenied"
        assert response.data == {
            "code": "permissionDenied",
            "detail": "Required scopes not given in token.",
            "instance": "/bevragingen/v1/verblijfplaatshistorie",
            "status": 403,
            "title": "You do not have permission to perform this action.",
            "type": "https://datatracker.ietf.org/doc/html/rfc7231#section-6.5.3",
        }

    def test_encrypted_bsn(self, api_client, requests_mock, common_headers, caplog):
        """Prove that search is possible"""
        requests_mock.post(
            "/lap/api/brp/verblijfplaatshistorie",
            json=self.RESPONSE_VERBLIJFPLAATS,
            headers={"content-type": "application/json"},
        )

        url = reverse("brp-verblijfplaatshistorie")
        token = build_jwt_token(["benk-brp-verblijfplaatshistorie-api", "benk-brp-encrypt-bsn"])

        # Create an encrypted BSN with the correlation id as salt to use in the request
        encrypted_bsn = encryption.encrypt("999993240", salt=common_headers["X-Correlation-ID"])

        response = api_client.post(
            url,
            {
                "type": "RaadpleegMetPeildatum",
                "burgerservicenummer": encrypted_bsn,
                "peildatum": "2020-09-24",
            },
            headers={
                "Authorization": f"Bearer {token}",
                **common_headers,
            },
        )
        assert response.status_code == 200, response

        # Assert the scope and unencrypted bsn show up in the logs
        for r in caplog.records:
            try:
                granted = r.granted.contains(SCOPE_ENCRYPT_BSN)
            except AttributeError:
                pass
            else:
                assert granted.contains(SCOPE_ENCRYPT_BSN)
                assert r.hc_request.contains("999993240")

    def test_null_values_added_2(self, api_client, requests_mock, common_headers):
        """Prove that null values can be added"""
        requests_mock.post(
            "/lap/api/brp/verblijfplaatshistorie",
            json=self.RESPONSE_VERBLIJFPLAATS,
            headers={"content-type": "application/json"},
        )

        url = reverse("brp-verblijfplaatshistorie")
        token = build_jwt_token(["benk-brp-verblijfplaatshistorie-api"])
        response = api_client.post(
            f"{url}?resultaat-formaat=volledig",
            {
                "type": "RaadpleegMetPeildatum",
                "burgerservicenummer": "999993240",
                "peildatum": "2020-09-24",
            },
            headers={
                "Authorization": f"Bearer {token}",
                **common_headers,
            },
        )
        assert response.status_code == 200, response
        assert response.json() == {
            "geheimhoudingPersoonsgegevens": None,  # included this missing field
            "opschortingBijhouding": {  # included this missing object
                "datum": None,  # included this missing field
            },
            "verblijfplaatsen": [
                {
                    "adresseerbaarObjectIdentificatie": "0518010000832200",
                    "adressering": {
                        "adresregel1": "Erasmusweg 471",
                        "adresregel2": "2532 CN  'S-GRAVENHAGE",
                        "inOnderzoek": None,  # included this missing field
                    },
                    "datumTot": None,  # included this missing field
                    "datumVan": {
                        "datum": "1990-04-27",
                        "langFormaat": "27 april 1990",
                        "type": "Datum",
                    },
                    "functieAdres": {
                        "code": "W",
                        "omschrijving": "woonadres",
                    },
                    "gemeenteVanInschrijving": {
                        "code": "0518",
                        "omschrijving": "'s-Gravenhage",
                    },
                    "inOnderzoek": None,  # included this missing field
                    "nummeraanduidingIdentificatie": "0518200000832199",
                    "type": "Adres",
                    "verblijfadres": {
                        "aanduidingBijHuisnummer": None,  # included this missing field
                        "huisletter": None,  # included this missing field
                        "huisnummer": 471,
                        "huisnummertoevoeging": None,  # included this missing field
                        "inOnderzoek": None,  # included this missing field
                        "korteStraatnaam": "Erasmusweg",
                        "officieleStraatnaam": "Erasmusweg",
                        "postcode": "2532CN",
                        "woonplaats": "'s-Gravenhage",
                    },
                    "verblijftNietOpAdresVanaf": None,  # included this missing field
                },
                {
                    "adresseerbaarObjectIdentificatie": None,  # included this missing field
                    "adressering": {
                        "adresregel1": "Erasmusweg 471",
                        "adresregel2": "2532 CN  'S-GRAVENHAGE",
                        "inOnderzoek": None,
                    },
                    "datumTot": None,  # included this missing field
                    "datumVan": None,  # included this missing field
                    "functieAdres": {
                        "code": "W",
                        "omschrijving": "woonadres",
                    },
                    "gemeenteVanInschrijving": {
                        "code": "0518",
                        "omschrijving": "'s-Gravenhage",
                    },
                    "inOnderzoek": None,  # included this missing field
                    "nummeraanduidingIdentificatie": "0518200000832199",
                    "type": "Locatie",
                    "verblijfadres": {
                        "huisnummer": 471,
                        "inOnderzoek": None,  # included this missing field
                        "korteStraatnaam": "Erasmusweg",
                        "locatiebeschrijving": None,  # included this missing field
                        "officieleStraatnaam": "Erasmusweg",
                        "postcode": "2532CN",
                        "woonplaats": "'s-Gravenhage",
                    },
                    "verblijftNietOpAdresVanaf": None,  # included this missing field
                },
            ],
        }
