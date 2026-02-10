from locust import tag, task
from requests import JSONDecodeError

from integration_tests.tasks.base import BaseTaskSet


@tag("personen")
class Personen(BaseTaskSet):
    path = "/personen"

    @task
    def raadpleeg_met_burgerservicenummer(self):
        data = {
            "type": "RaadpleegMetBurgerservicenummer",
            "burgerservicenummer": ["010082426"],
        }
        with self.client.post(self.url, json=data, catch_response=True) as response:
            try:
                if response.json()["personen"][0]["aNummer"] == "9358151057":
                    response.success()
            except (KeyError, JSONDecodeError):
                response.failure("Expected output not in response")

    @task
    def raadpleeg_met_burgerservicenummer_non_existing(self):
        data = {
            "type": "RaadpleegMetBurgerservicenummer",
            "burgerservicenummer": ["010239005"],
        }
        with self.client.post(self.url, json=data, catch_response=True) as response:
            if response.status_code == 404:
                response.success()

    @task
    def zoek_met_adresseerbaar_object_identificatie(self):
        data = {
            "type": "ZoekMetAdresseerbaarObjectIdentificatie",
            "adresseerbaarObjectIdentificatie": "0363010012064483",
        }
        with self.client.post(self.url, json=data, catch_response=True) as response:
            try:
                if len(response.json()["personen"]) == 2:
                    response.success()
            except (KeyError, JSONDecodeError):
                response.failure("Expected output not in response")

    @task
    def zoek_met_geslachtsnaam_en_geboortedatum(self):
        data = {
            "type": "ZoekMetGeslachtsnaamEnGeboortedatum",
            "geboortedatum": "1939-03-15",
            "geslachtsnaam": "Verstratenmaker",
        }
        with self.client.post(self.url, json=data, catch_response=True) as response:
            try:
                if response.json()["personen"][0]["burgerservicenummer"] == "010082426":
                    response.success()
            except (KeyError, JSONDecodeError):
                response.failure("Expected output not in response")

    @task
    def zoek_met_naam_en_gemeente_van_inschrijving(self):
        data = {
            "type": "ZoekMetNaamEnGemeenteVanInschrijving",
            "gemeenteVanInschrijving": "0363",
            "geslachtsnaam": "Verstratenmaker",
            "voornamen": "Pieter",
        }
        with self.client.post(self.url, json=data, catch_response=True) as response:
            try:
                if response.json()["personen"][0]["burgerservicenummer"] == "010082426":
                    response.success()
            except (KeyError, JSONDecodeError):
                response.failure("Expected output not in response")

    @task
    def zoek_met_nummeraanduiding_identificatie(self):
        data = {
            "type": "ZoekMetNummeraanduidingIdentificatie",
            "nummeraanduidingIdentificatie": "0363200012064527",
        }
        with self.client.post(self.url, json=data, catch_response=True) as response:
            try:
                if len(response.json()["personen"]) == 2:
                    response.success()
            except (KeyError, JSONDecodeError):
                response.failure("Expected output not in response")

    @task
    def zoek_met_postcode_en_huisnummer(self):
        data = {
            "type": "ZoekMetPostcodeEnHuisnummer",
            "postcode": "1046BV",
            "huisnummer": "6",
        }
        with self.client.post(self.url, json=data, catch_response=True) as response:
            try:
                if len(response.json()["personen"]) == 2:
                    response.success()
            except (KeyError, JSONDecodeError):
                response.failure("Expected output not in response")

    @task
    def zoek_met_straat_huisnummer_en_gemeente_van_inschrijving(self):
        data = {
            "type": "ZoekMetStraatHuisnummerEnGemeenteVanInschrijving",
            "straat": "Vaalmuiden",
            "huisnummer": "6",
            "gemeenteVanInschrijving": "0363",
        }
        with self.client.post(self.url, json=data, catch_response=True) as response:
            try:
                if len(response.json()["personen"]) == 2:
                    response.success()
            except (KeyError, JSONDecodeError):
                response.failure("Expected output not in response")
