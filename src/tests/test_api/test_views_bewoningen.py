from django.urls import reverse

from tests.utils import build_jwt_token


class TestBrpBewoningenView:
    """Prove that the API works as advertised."""

    RESPONSE_BEWONINGEN = {
        "bewoningen": [
            {
                "adresseerbaarObjectIdentificatie": "0518010000832200",
                "periode": {"datumVan": "2020-09-24", "datumTot": "2020-09-25"},
                "bewoners": [{"burgerservicenummer": "999993240"}],
                "mogelijkeBewoners": [{"burgerservicenummer": "999993241"}],
            },
            {
                "adresseerbaarObjectIdentificatie": "0518010000832200",
                "periode": {"datumVan": "2016-03-02", "datumTot": "2020-09-24"},
                "bewoners": [{"burgerservicenummer": "999991371"}],
                "mogelijkeBewoners": [],
            },
        ]
    }

    def test_address_id_search(self, api_client, requests_mock, common_headers, caplog):
        """Prove that search is possible"""
        requests_mock.post(
            "/lap/api/brp/bewoning/bewoningen",
            json=self.RESPONSE_BEWONINGEN,
            headers={"content-type": "application/json"},
        )

        url = reverse("brp-bewoningen")
        token = build_jwt_token(["benk-brp-bewoning-api"])
        response = api_client.post(
            url,
            {
                "type": "BewoningMetPeildatum",
                "adresseerbaarObjectIdentificatie": "0518010000832200",
                "peildatum": "2020-09-24",
            },
            headers={
                "Authorization": f"Bearer {token}",
                **common_headers,
            },
        )

        assert response.status_code == 200, response
        assert response.json() == self.RESPONSE_BEWONINGEN, response.data

        log_messages = caplog.messages
        for log_message in [
            (
                "User text@example.com retrieved using 'bewoningen.BewoningMetPeildatum':"
                " burgerservicenummer=999993240"
            ),
            (
                "User text@example.com retrieved using 'bewoningen.BewoningMetPeildatum':"
                " burgerservicenummer=999993241"
            ),
            (
                "User text@example.com retrieved using 'bewoningen.BewoningMetPeildatum':"
                " burgerservicenummer=999991371"
            ),
        ]:
            assert log_message in log_messages

        # Log messages about retrieved BSN's should contain the full request/response context
        assert any("retrieved using" in record.message for record in caplog.records)
        for record in caplog.records:
            if "retrieved using" in record.message:
                assert all(
                    getattr(record, attr) for attr in ["request", "hcRequest", "hcResponse"]
                )

    def test_address_id_search_deny(self, api_client, common_headers):
        """Prove that access is checked"""
        url = reverse("brp-bewoningen")
        token = build_jwt_token(["benk-brp-SOME-OTHER-api"])
        response = api_client.post(
            url,
            {
                "type": "BewoningMetPeildatum",
                "adresseerbaarObjectIdentificatie": "0518010000832200",
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
            "instance": "/bevragingen/v1/bewoningen",
            "status": 403,
            "title": "You do not have permission to perform this action.",
            "type": "https://datatracker.ietf.org/doc/html/rfc7231#section-6.5.3",
        }

    def test_null_values_added(self, api_client, requests_mock, common_headers):
        """Prove that null values can be added"""
        requests_mock.post(
            "/lap/api/brp/bewoning/bewoningen",
            json=self.RESPONSE_BEWONINGEN,
            headers={"content-type": "application/json"},
        )

        url = reverse("brp-bewoningen")
        token = build_jwt_token(["benk-brp-bewoning-api"])
        response = api_client.post(
            f"{url}?resultaat-formaat=volledig",
            {
                "type": "BewoningMetPeildatum",
                "adresseerbaarObjectIdentificatie": "0518010000832200",
                "peildatum": "2020-09-24",
            },
            headers={
                "Authorization": f"Bearer {token}",
                **common_headers,
            },
        )
        assert response.status_code == 200, response
        assert response.json() == {
            "bewoningen": [
                {
                    "adresseerbaarObjectIdentificatie": "0518010000832200",
                    "bewoners": [
                        {
                            "burgerservicenummer": "999993240",
                            "geboorte": {  # included this missing object
                                "datum": None,  # included this missing field
                            },
                            "geheimhoudingPersoonsgegevens": None,  # included this missing field
                            "inOnderzoek": None,  # included this missing field
                            "naam": {  # included this missing object
                                "volledigeNaam": None,  # included this missing field
                            },
                        },
                    ],
                    "indicatieVeelBewoners": None,  # included this missing field
                    "mogelijkeBewoners": [
                        {
                            "burgerservicenummer": "999993241",
                            "geboorte": {  # included this missing object
                                "datum": None,  # included this missing field
                            },
                            "geheimhoudingPersoonsgegevens": None,  # included this missing field
                            "inOnderzoek": None,  # included this missing field
                            "naam": {  # included this missing object
                                "volledigeNaam": None,  # included this missing field
                            },
                        },
                    ],
                    "periode": {
                        "datumTot": "2020-09-25",
                        "datumVan": "2020-09-24",
                    },
                },
                {
                    "adresseerbaarObjectIdentificatie": "0518010000832200",
                    "bewoners": [
                        {
                            "burgerservicenummer": "999991371",
                            "geboorte": {  # included this missing object
                                "datum": None,  # included this missing field
                            },
                            "geheimhoudingPersoonsgegevens": None,  # included this missing field
                            "inOnderzoek": None,
                            "naam": {  # included this missing object
                                "volledigeNaam": None,  # included this missing field
                            },
                        },
                    ],
                    "indicatieVeelBewoners": None,  # included this missing field
                    "mogelijkeBewoners": [],
                    "periode": {
                        "datumTot": "2020-09-24",
                        "datumVan": "2016-03-02",
                    },
                },
            ],
        }
