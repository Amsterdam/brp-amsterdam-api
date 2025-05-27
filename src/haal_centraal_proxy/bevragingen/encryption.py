from typing import Any

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from django.conf import settings


class DecryptionFailed(Exception):

    def __init__(self, detail: str):
        super().__init__(detail)
        self.detail = detail


def decrypt(value: Any, salt: str | None = None) -> str:
    fernet = _get_fernet()
    try:
        decrypted_value = fernet.decrypt(value.encode("utf-8")).decode("utf-8")
    except InvalidToken as err:
        raise DecryptionFailed(
            "U bent niet geautoriseerd voor niet versleutelde burgerservicenummers."
        ) from err

    # Validate the salt
    if salt and salt not in decrypted_value:
        raise DecryptionFailed("Geen toegang tot versleutelde waarde.")
    return decrypted_value.replace(f":{salt}", "")


def encrypt(value: Any, salt: str | None = None) -> str:
    fernet = _get_fernet()
    if not isinstance(value, str):
        value = str(value)
    if salt:
        value = f"{value}:{salt}"
    return fernet.encrypt(value.encode("utf-8")).decode("utf-8")


def _get_keys() -> list[bytes]:
    return [key.encode("utf-8") for key in settings.HAAL_CENTRAAL_BRP_ENCRYPTION_KEYS]


def _get_fernet() -> MultiFernet:
    return MultiFernet([Fernet(k) for k in _get_keys()])
