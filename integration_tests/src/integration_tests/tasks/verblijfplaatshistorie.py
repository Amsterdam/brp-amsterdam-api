from locust import tag, task
from requests import JSONDecodeError

from integration_tests.tasks.base import BaseTaskSet


@tag("verblijfplaatshistorie")
class Verblijfplaatshistorie(BaseTaskSet):
    path = "/verblijfplaatshistorie"

    @task
    def raadpleeg_met_peildatum(self):
        data = {
            "type": "RaadpleegMetPeildatum",
            "burgerservicenummer": "010082426",
            "peildatum": "2025-01-01",
        }
        with self.client.post(self.url, json=data, catch_response=True) as response:
            try:
                expected_result = {
                    "adresregel1": "Vaalmuiden 6",
                    "adresregel2": "1046 BV  AMSTERDAM",
                }
                if response.json()["verblijfplaatsen"][0]["adressering"] == expected_result:
                    response.success()
            except (KeyError, JSONDecodeError):
                response.failure("Expected output not in response")

    @task
    def raadpleeg_met_periode(self):
        data = {
            "type": "RaadpleegMetPeriode",
            "burgerservicenummer": "010082426",
            "datumVan": "2019-01-01",
            "datumTot": "2020-01-01",
        }
        with self.client.post(self.url, json=data, catch_response=True) as response:
            try:
                expected_result = {
                    "adresregel1": "Bloemstraat 17 a",
                    "adresregel2": "8603 XV  SNEEK",
                }
                if response.json()["verblijfplaatsen"][0]["adressering"] == expected_result:
                    response.success()
            except (KeyError, JSONDecodeError):
                response.failure("Expected output not in response")
