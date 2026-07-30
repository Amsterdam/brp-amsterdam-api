from datetime import datetime

from brp_amsterdam_api.bevragingen.clients import tables

MONTH_NAMES = [
    "januari",
    "februari",
    "maart",
    "april",
    "mei",
    "juni",
    "juli",
    "augustus",
    "september",
    "oktober",
    "november",
    "december",
]


def derive_date(value: str) -> dict:
    """
    Derive a date dictionary from a string value in the format YYYYMMDD. The value may contain
    0s for unknown months or days. For example, 19650000 means the year is known but not the
    month or day.
    """
    if not value.endswith("00"):
        date_value = datetime.strptime(value, "%Y%m%d").astimezone()
        return {
            "type": "Datum",
            "datum": date_value.strftime("%Y-%m-%d"),
            "langFormaat": f"{date_value.day} {MONTH_NAMES[date_value.month - 1]} "
            f"{date_value.year}",
        }

    year = value[:4]
    month = value[4:6]

    if month != "00":
        month_number = int(month)
        month_name = MONTH_NAMES[month_number - 1]
        return {
            "type": "Datum",
            "datum": f"{year}-{month}-00",
            "langFormaat": f"{month_name} {year}",
        }

    return {
        "type": "Datum",
        "datum": f"{year}-00-00",
        "langFormaat": year,
    }


def derive_initials(first_names) -> str:
    """
    Return initials based on first names. Only look for space as a separator.

    For example the following names will return:
    - Kees John -> K.J.
    - Anne-Fleur -> A.
    - Jan-Willem Gerard -> J.G.
    - Ijsbrand -> I.
    """
    initials = [n[:1] for n in first_names.split(" ")]
    return ".".join(initials + [""])


def derive_description(value, table_name) -> str:
    table = getattr(tables, table_name)
    if not value:
        return table["0000"]

    try:
        return table[value]
    except KeyError:
        return value
