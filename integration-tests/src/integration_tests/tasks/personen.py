import logging

from integration_tests.tasks.base import BaseTaskSet
from locust import tag, task

logger = logging.getLogger(__name__)


@tag("personen")
class Personen(BaseTaskSet):
    path = "/personen"

    def validate_payload_structure(self, payload, request_type) -> bool:
        personen = payload.get("personen") if isinstance(payload, dict) else None
        return isinstance(personen, list) and payload.get("type") == request_type

    @task
    def raadpleeg_met_burgerservicenummer(self):
        request_type = "RaadpleegMetBurgerservicenummer"
        data = {
            "type": request_type,
            "burgerservicenummer": ["010082426"],
        }
        with self.client.post(self.url, json=data, catch_response=True) as response:
            payload = self.response_json_or_failure(response)
            if payload is None:
                return

            if self.validate_payload_structure(payload, request_type):
                response.success()
            else:
                response.failure("Expected output structure not in response")

    @task
    def raadpleeg_met_burgerservicenummer_non_existing(self):
        request_type = "RaadpleegMetBurgerservicenummer"
        data = {
            "type": request_type,
            "burgerservicenummer": ["010239005"],
        }
        with self.client.post(self.url, json=data, catch_response=True) as response:
            payload = self.response_json_or_failure(response)
            if payload is None:
                return

            if self.validate_payload_structure(payload, request_type):
                response.success()
            else:
                response.failure("Expected output structure not in response")

    @task
    def zoek_met_adresseerbaar_object_identificatie(self):
        request_type = "ZoekMetAdresseerbaarObjectIdentificatie"
        data = {
            "type": request_type,
            "adresseerbaarObjectIdentificatie": "0363010012064483",
        }
        with self.client.post(self.url, json=data, catch_response=True) as response:
            payload = self.response_json_or_failure(response)
            if payload is None:
                return

            if self.validate_payload_structure(payload, request_type):
                response.success()
            else:
                response.failure("Expected output structure not in response")

    @task
    def zoek_met_geslachtsnaam_en_geboortedatum(self):
        request_type = "ZoekMetGeslachtsnaamEnGeboortedatum"
        data = {
            "type": request_type,
            "geboortedatum": "1939-03-15",
            "geslachtsnaam": "Verstratenmaker",
        }
        with self.client.post(self.url, json=data, catch_response=True) as response:
            payload = self.response_json_or_failure(response)
            if payload is None:
                return

            if self.validate_payload_structure(payload, request_type):
                response.success()
            else:
                response.failure("Expected output structure not in response")

    @task
    def zoek_met_naam_en_gemeente_van_inschrijving(self):
        request_type = "ZoekMetNaamEnGemeenteVanInschrijving"
        data = {
            "type": request_type,
            "gemeenteVanInschrijving": "0363",
            "geslachtsnaam": "Verstratenmaker",
            "voornamen": "Pieter",
        }
        with self.client.post(self.url, json=data, catch_response=True) as response:
            payload = self.response_json_or_failure(response)
            if payload is None:
                return

            if self.validate_payload_structure(payload, request_type):
                response.success()
            else:
                response.failure("Expected output structure not in response")

    @task
    def zoek_met_nummeraanduiding_identificatie(self):
        request_type = "ZoekMetNummeraanduidingIdentificatie"
        data = {
            "type": request_type,
            "nummeraanduidingIdentificatie": "0363200012064527",
        }
        with self.client.post(self.url, json=data, catch_response=True) as response:
            payload = self.response_json_or_failure(response)
            if payload is None:
                return

            if self.validate_payload_structure(payload, request_type):
                response.success()
            else:
                response.failure("Expected output structure not in response")

    @task
    def zoek_met_postcode_en_huisnummer(self):
        request_type = "ZoekMetPostcodeEnHuisnummer"
        data = {
            "type": request_type,
            "postcode": "1046BV",
            "huisnummer": "6",
        }
        with self.client.post(self.url, json=data, catch_response=True) as response:
            payload = self.response_json_or_failure(response)
            if payload is None:
                return

            if self.validate_payload_structure(payload, request_type):
                response.success()
            else:
                response.failure("Expected output structure not in response")

    @task
    def zoek_met_straat_huisnummer_en_gemeente_van_inschrijving(self):
        request_type = "ZoekMetStraatHuisnummerEnGemeenteVanInschrijving"
        data = {
            "type": request_type,
            "straat": "Vaalmuiden",
            "huisnummer": "6",
            "gemeenteVanInschrijving": "0363",
        }
        with self.client.post(self.url, json=data, catch_response=True) as response:
            payload = self.response_json_or_failure(response)
            if payload is None:
                return

            if self.validate_payload_structure(payload, request_type):
                response.success()
            else:
                response.failure("Expected output structure not in response")
