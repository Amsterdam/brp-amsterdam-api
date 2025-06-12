from django.urls import reverse


class TestHealthCheck:
    RESPONSE_HEALTHCHECK = {
        "invalidParams": [
            {"name": "type", "code": "value", "reason": "Waarde is geen geldig zoek type."}
        ],
        "type": "https://datatracker.ietf.org/doc/html/rfc7231#section-6.5.1",
        "title": "Een of meerdere parameters zijn niet correct.",
        "status": 400,
        "detail": "De foutieve parameter(s) zijn: type.",
        "instance": "/lap/api/brp",
        "code": "paramsValidation",
    }

    def test_backend_health_endpoint(self, api_client, requests_mock, caplog, common_headers):
        """Prove that incorrect API-key settings are handled gracefully."""
        requests_mock.post(
            "/lap/api/brp",
            json=self.RESPONSE_HEALTHCHECK,
            status_code=400,
            headers={"content-type": "application/json"},
        )

        url = reverse("brp-personen-health")
        response = api_client.get(url)
        assert response.status_code == 200
        assert response.json() == {
            "success": True,
            "response": self.RESPONSE_HEALTHCHECK,
        }
