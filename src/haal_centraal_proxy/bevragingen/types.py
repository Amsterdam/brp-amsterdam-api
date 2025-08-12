from typing import Literal, NotRequired, TypedDict


class BaseQuery(TypedDict):
    type: str


class BasePersonenQuery(BaseQuery):
    """Typing interface for the incoming request to Haal Centraal.
    Some bits are required by Haal Centraal, but not required in this API.
    When they are omitted, defaults will be inserted.
    """

    type: Literal[
        "RaadpleegMetBurgerservicenummer",
        "ZoekMetAdresseerbaarObjectIdentificatie",
        "ZoekMetGeslachtsnaamEnGeboortedatum",
        "ZoekMetNaamEnGemeenteVanInschrijving",
        "ZoekMetNummeraanduidingIdentificatie",
        "ZoekMetPostcodeEnHuisnummer",
        "ZoekMetStraatHuisnummerEnGemeenteVanInschrijving",
    ]
    fields: NotRequired[list[str]]  # required by HC, not here (we insert a default)
    gemeenteVanInschrijving: NotRequired[str]


class PersonenQuery(BasePersonenQuery):
    # Depends on the different subtypes, flattened here:
    inclusiefOverledenPersonen: NotRequired[bool]

    burgerservicenummer: NotRequired[list[str]]
    geboortedatum: NotRequired[str]

    geslachtsnaam: NotRequired[str]
    geslacht: NotRequired[str]
    voorvoegsel: NotRequired[str]
    voornamen: NotRequired[str]

    straat: NotRequired[str]
    huisletter: NotRequired[str]
    huisnummer: NotRequired[str]
    huisnummertoevoeging: NotRequired[str]
    postcode: NotRequired[str]

    verblijfplaats: NotRequired[str]
    nummeraanduidingIdentificatie: NotRequired[str]
    adresseerbaarObjectIdentificatie: NotRequired[str]


class BaseResponse(TypedDict):
    pass


class PersonenResponse(TypedDict):
    """Stub for the BRP Personen API response"""

    type: str
    personen: list[dict]


class Bewoning(TypedDict):
    adresseerbaarObjectIdentificatie: str
    periode: dict[str, str]
    bewoners: list[dict]
    mogelijkeBewoners: list[dict]
    indicatieVeelBewoners: bool


class BewoningenResponse(TypedDict):
    """Stub for the BRP Bewoningen API response"""

    bewoningen: list[Bewoning]


class VerblijfsplaatshistorieResponse(TypedDict):
    """Stub for the BRP Verblijfsplaatshistorie API response"""

    bewoningen: list[Bewoning]
