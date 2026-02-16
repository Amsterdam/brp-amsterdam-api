import csv

from django.conf import settings


def read_table_file(table_file) -> dict:
    file_path = f"{settings.SRC_DIR}/brp_amsterdam_api/bevragingen/clients/tables/{table_file}"
    with open(file_path, encoding="utf-8") as file:
        csv_reader = csv.DictReader(file, delimiter=";")
        return {row["code"]: row["omschrijving"] for row in csv_reader}


CITY_CODE_TABLE = read_table_file("tabel33_gemeententabel.csv")
COUNTRY_CODE_TABLE = read_table_file("tabel34_landentabel.csv")
GENDER_CODE_TABLE = {
    "V": "vrouw",
    "M": "man",
    "O": "onbekend",
    "0000": "onbekend",
}

ENGAGEMENT_TYPE_TABLE = {
    "H": "huwelijk",
    "P": "geregistreerd partnerschap",
    "0000": ".",
}

REASON_DISSOLUTION_TABLE = {
    ".": "onbekend",
    "A": "vermissing van een persoon gevolgd door ander huwelijk/geregistr. partnerschap",
    "N": "nietigverklaring",
    "O": "overlijden echtgenoot/geregistreerd partner",
    "R": "rechtsvermoeden van overlijden echtgenoot/geregistreerd partner",
    "S": "echtsch of huw.ontb na sch van tfl en bed/eindigen partnersch door ovk of ontb",
    "V": "een naar vreemd recht anders beëind. huwelijk/geregistr. partnerschap",
}
