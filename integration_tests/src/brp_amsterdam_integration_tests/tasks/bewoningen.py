from brp_amsterdam_integration_tests.tasks.base import BaseTaskSet
from locust import task


class Bewoningen(BaseTaskSet):
    path = "/bewoningen"

    @task
    def bewoning_met_peildatum(self):
        data = {
            "type": "BewoningMetPeildatum",
            "adresseerbaarObjectIdentificatie": "0363010001026774",
            "peildatum": "2020-01-01",
        }
        self.client.post(self.url, json=data)

    @task
    def bewoning_met_periode(self):
        data = {
            "type": "BewoningMetPeriode",
            "adresseerbaarObjectIdentificatie": "0363010001026774",
            "datumVan": "2019-01-01",
            "datumTot": "2020-01-01",
        }
        self.client.post(self.url, json=data)
