from locust import tag, task

from integration_tests.tasks.base import BaseTaskSet


@tag("partnerhistorie")
class Partnerhistorie(BaseTaskSet):
    path = "/partnerhistorie"

    def _validate_payload_structure(self, payload, request_type) -> bool:
        partnerhistorie = payload.get("partnerhistorie") if isinstance(payload, dict) else None
        return isinstance(partnerhistorie, list) and payload.get("type") == request_type

    @task
    def raadpleeg_met_burgerservicenummer(self):
        request_type = "RaadpleegMetBurgerservicenummer"
        data = {
            "type": request_type,
            "burgerservicenummer": "999998754",
        }
        with self.client.post(self.url, json=data, catch_response=True) as response:
            payload = self.response_json_or_failure(response)
            if payload is None:
                return

            if self._validate_payload_structure(payload, request_type):
                response.success()
            else:
                response.failure("Expected output structure not in response")
