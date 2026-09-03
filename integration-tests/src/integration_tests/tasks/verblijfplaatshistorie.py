from integration_tests.tasks.base import BaseTaskSet
from locust import tag, task


@tag("verblijfplaatshistorie")
class Verblijfplaatshistorie(BaseTaskSet):
    path = "/verblijfplaatshistorie"

    def _validate_payload_structure(self, payload) -> bool:
        verblijfplaatsen = payload.get("verblijfplaatsen") if isinstance(payload, dict) else None
        return isinstance(verblijfplaatsen, list)

    @task
    def raadpleeg_met_peildatum(self):
        data = {
            "type": "RaadpleegMetPeildatum",
            "burgerservicenummer": "010082426",
            "peildatum": "2025-01-01",
        }
        with self.client.post(self.url, json=data, catch_response=True) as response:
            payload = self.response_json_or_failure(response)
            if payload is None:
                return

            if self._validate_payload_structure(payload):
                response.success()
            else:
                response.failure("Expected output structure not in response")

    @task
    def raadpleeg_met_periode(self):
        data = {
            "type": "RaadpleegMetPeriode",
            "burgerservicenummer": "010082426",
            "datumVan": "2019-01-01",
            "datumTot": "2020-01-01",
        }
        with self.client.post(self.url, json=data, catch_response=True) as response:
            payload = self.response_json_or_failure(response)
            if payload is None:
                return

            if self._validate_payload_structure(payload):
                response.success()
            else:
                response.failure("Expected output structure not in response")
