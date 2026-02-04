from brp_amsterdam_integration_tests.tasks.base import BaseTaskSet
from locust import task


class Personen(BaseTaskSet):
    path = "/personen"

    @task
    def raadpleeg_met_burgerservicenummer(self):
        data = {
            "type": "RaadpleegMetBurgerservicenummer",
            "burgerservicenummer": ["999995297"],
        }
        self.client.post(self.url, json=data)

    @task
    def zoek_met_adresseerbaar_object_identificatie(self):
        data = {
            "type": "ZoekMetAdresseerbaarObjectIdentificatie",
            "adresseerbaarObjectIdentificatie": "0363010001026774",
        }
        self.client.post(self.url, json=data)

    @task
    def zoek_met_geslachtsnaam_en_geboortedatum(self):
        data = {
            "type": "ZoekMetGeslachtsnaamEnGeboortedatum",
            "geboortedatum": "2010-05-01",
            "geslachtsnaam": "Precise",
        }
        self.client.post(self.url, json=data)

    @task
    def zoek_met_naam_en_gemeente_van_inschrijving(self):
        data = {
            "type": "ZoekMetNaamEnGemeenteVanInschrijving",
            "gemeenteVanInschrijving": "0363",
            "geslachtsnaam": "Precise",
            "voornamen": "Xena",
        }
        self.client.post(self.url, json=data)

    @task
    def zoek_met_nummeraanduiding_identificatie(self):
        data = {
            "type": "ZoekMetNummeraanduidingIdentificatie",
            "nummeraanduidingIdentificatie": "0363200000496683",
        }
        self.client.post(self.url, json=data)

    @task
    def zoek_met_postcode_en_huisnummer(self):
        data = {
            "type": "ZoekMetPostcodeEnHuisnummer",
            "postcode": "1013BL",
            "huisnummer": "5",
        }
        self.client.post(self.url, json=data)

    @task
    def zoek_met_straat_huisnummer_en_gemeente_van_inschrijving(self):
        data = {
            "type": "ZoekMetStraatHuisnummerEnGemeenteVanInschrijving",
            "straat": "Papierweg",
            "huisnummer": "5",
            "gemeenteVanInschrijving": "0363",
        }
        self.client.post(self.url, json=data)
