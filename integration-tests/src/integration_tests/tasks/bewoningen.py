from integration_tests.tasks.base import BaseTaskSet
from locust import tag, task


@tag("bewoningen")
class Bewoningen(BaseTaskSet):
    path = "/bewoningen"

    def _validate_payload_structure(self, payload) -> bool:
        bewoningen = payload.get("bewoningen") if isinstance(payload, dict) else None
        return isinstance(bewoningen, list)

    @task
    def bewoning_met_peildatum(self):
        data = {
            "type": "BewoningMetPeildatum",
            "adresseerbaarObjectIdentificatie": "0363010012064483",
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
    def bewoning_met_periode(self):
        data = {
            "type": "BewoningMetPeriode",
            "adresseerbaarObjectIdentificatie": "0363010012064483",
            "datumVan": "2025-01-01",
            "datumTot": "2025-01-02",
        }
        with self.client.post(self.url, json=data, catch_response=True) as response:
            payload = self.response_json_or_failure(response)
            if payload is None:
                return

            if self._validate_payload_structure(payload):
                response.success()
            else:
                response.failure("Expected output structure not in response")
