import uuid

import settings
from locust import HttpUser
from tasks import Bewoningen, Personen, Verblijfsplaatshistorie


class BRPUser(HttpUser):
    host: str = settings.BRP_URL
    base_path: str = "/bevragingen/v1"
    base_url: str = host + base_path

    tasks = {Personen, Bewoningen, Verblijfsplaatshistorie}

    def on_start(self):
        self.client.headers = {
            "X-User": "BRP DADI Integration Tests",
            "X-Correlation-ID": str(uuid.uuid4()),
            "X-Task-Description": "Integration Tests",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.environment.token}",
        }
