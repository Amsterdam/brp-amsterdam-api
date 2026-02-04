from brp_amsterdam_integration_tests.tasks.base import BaseTaskSet
from locust import task


class Verblijfsplaatshistorie(BaseTaskSet):
    path = "/verblijfsplaatshistorie"

    @task
    def raadpleeg_met_peildatum(self):
        data = {
            "type": "RaadpleegMetPeildatum",
            "burgerservicenummer": "999995297",
            "peildatum": "2020-01-01",
        }
        self.client.post(self.url, json=data)

    @task
    def raadpleeg_met_periode(self):
        data = {
            "type": "RaadpleegMetPeriode",
            "burgerservicenummer": "999995297",
            "datumVan": "2019-01-01",
            "datumTot": "2020-01-01",
        }
        self.client.post(self.url, json=data)
