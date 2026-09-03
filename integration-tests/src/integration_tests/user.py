import uuid

from integration_tests import settings
from integration_tests.tasks import (
    Bewoningen,
    Partnerhistorie,
    Personen,
    Verblijfplaatshistorie,
)
from locust import HttpUser


class BRPUser(HttpUser):
    host: str = settings.BRP_AMSTERDAM_URL
    base_path: str = "/bevragingen/v1"
    base_url: str = f"{host}{base_path}"

    tasks = {Personen, Bewoningen, Verblijfplaatshistorie, Partnerhistorie}

    def on_start(self):
        self.client.headers = {
            "X-User": "BRP DADI Integration Tests",
            "X-Correlation-ID": str(uuid.uuid4()),
            "X-Task-Description": "Integration Tests",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.environment.token}",
        }
