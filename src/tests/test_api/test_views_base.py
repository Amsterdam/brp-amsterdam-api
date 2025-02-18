import pytest
from django.urls import reverse

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
        assert response.status_code == 401
        assert response.data == {
            "type": "https://datatracker.ietf.org/doc/html/rfc7235#section-3.1",
            "code": "notAuthenticated",
            "title": "Authentication credentials were not provided.",
            "detail": "",
            "status": 401,
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
            [
                "benk-brp-personen-api",
                "benk-brp-zoekvraag-postcode-huisnummer",
                "benk-brp-gegevensset-1",
            ]
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
            "code": "backendConfig",
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
            ["benk-brp-personen-api", "benk-brp-zoekvraag-bsn", "benk-brp-gegevensset-1"]
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
