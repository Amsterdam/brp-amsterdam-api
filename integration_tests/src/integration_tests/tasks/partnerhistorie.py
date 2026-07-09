from locust import tag, task
from requests import JSONDecodeError

from integration_tests.tasks.base import BaseTaskSet


@tag("partnerhistorie")
class Partnerhistorie(BaseTaskSet):
    path = "/partnerhistorie"

    @task
    def raadpleeg_met_burgerservicenummer(self):
        data = {
            "type": "RaadpleegMetBurgerservicenummer",
            "burgerservicenummer": "999998754",
        }
        with self.client.post(self.url, json=data, catch_response=True) as response:
            try:
                if response.json()["partnerhistorie"][0]["bugerservicenummer"] == "999998729":
                    response.success()
            except (KeyError, JSONDecodeError):
                response.failure("Expected output not in response")
