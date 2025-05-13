import base64
from typing import Any

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from django.conf import settings


class DecryptionFailed(Exception):
    pass


def decrypt(value: Any) -> str:
    fernet = _get_fernet()
    try:
        decrypted_value = fernet.decrypt(bytes(value, "utf-8")).decode("utf-8")
    except InvalidToken as err:
        raise DecryptionFailed("Value failed to decrypt") from err
    return decrypted_value


def encrypt(value: Any) -> str:
    fernet = _get_fernet()
    if not isinstance(value, str):
        value = str(value)
    return fernet.encrypt(bytes(value, "utf-8")).decode("utf-8")


def _get_keys() -> list[bytes]:
    keys = []
    secret_key = settings.SECRET_KEY
    salt_keys = settings.HAAL_CENTRAAL_BRP_ENCRYPTION_SALTS
    for salt_key in salt_keys:
        salt = bytes(salt_key, "utf-8")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=1_200_000,
        )
        keys.append(base64.urlsafe_b64encode(kdf.derive(secret_key.encode("utf-8"))))
    return keys


def _get_fernet() -> MultiFernet:
    return MultiFernet([Fernet(k) for k in _get_keys()])
