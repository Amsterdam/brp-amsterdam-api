import base64
import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from django.conf import settings

_NONCE_SIZE = 12


class DecryptionFailed(Exception):

    def __init__(self, detail: str):
        super().__init__(detail)
        self.detail = detail


def decrypt(value: Any, salt: str | None = None) -> str:
    if not isinstance(value, str):
        value = str(value)
    try:
        raw = _urlsafe_b64decode(value.encode("utf-8"))
        nonce, ciphertext = raw[:_NONCE_SIZE], raw[_NONCE_SIZE:]
        decrypted_value = _decrypt_with_any_key(nonce, ciphertext)
    except (ValueError, InvalidTag) as err:
        raise DecryptionFailed(
            "U bent niet geautoriseerd voor niet versleutelde burgerservicenummers."
        ) from err

    # Validate the salt
    if salt and salt not in decrypted_value:
        raise DecryptionFailed("Geen toegang tot versleutelde waarde.")
    return decrypted_value.replace(f":{salt}", "")


def encrypt(value: Any, salt: str | None = None) -> str:
    if not isinstance(value, str):
        value = str(value)
    if salt:
        value = f"{value}:{salt}"

    nonce = os.urandom(_NONCE_SIZE)
    aesgcm = AESGCM(_get_keys()[0])
    ciphertext = aesgcm.encrypt(nonce, value.encode("utf-8"), None)
    return _urlsafe_b64encode(nonce + ciphertext).decode("utf-8")


def _decrypt_with_any_key(nonce: bytes, ciphertext: bytes) -> str:
    # Mirrors MultiFernet: try each configured key in order for key rotation support.
    for key in _get_keys():
        try:
            return AESGCM(key).decrypt(nonce, ciphertext, None).decode("utf-8")
        except InvalidTag:
            continue
    raise InvalidTag()


def _get_keys() -> list[bytes]:
    return [_urlsafe_b64decode(key.encode("utf-8")) for key in settings.BRP_ENCRYPTION_KEYS]


def _urlsafe_b64encode(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data)


def _urlsafe_b64decode(data: bytes) -> bytes:
    return base64.urlsafe_b64decode(data)
