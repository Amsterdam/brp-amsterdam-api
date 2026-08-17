from locust import tag, task
from requests import JSONDecodeError

from integration_tests.tasks.base import BaseTaskSet


@tag("bewoningen")
class Bewoningen(BaseTaskSet):
    path = "/bewoningen"

    @task
    def bewoning_met_peildatum(self):
        data = {
            "type": "BewoningMetPeildatum",
            "adresseerbaarObjectIdentificatie": "0363010012064483",
            "peildatum": "2025-01-01",
        }
        with self.client.post(self.url, json=data, catch_response=True) as response:
            try:
                if len(response.json()["bewoningen"][0]["bewoners"]) == 2:
                    response.success()
            except (KeyError, JSONDecodeError):
                response.failure("Expected output not in response")

    @task
    def bewoning_met_periode(self):
        data = {
            "type": "BewoningMetPeriode",
            "adresseerbaarObjectIdentificatie": "0363010012064483",
            "datumVan": "2025-01-01",
            "datumTot": "2025-01-02",
        }
        with self.client.post(self.url, json=data, catch_response=True) as response:
            try:
                if len(response.json()["bewoningen"][0]["bewoners"]) == 2:
                    response.success()
            except (KeyError, JSONDecodeError):
                response.failure("Expected output not in response")
