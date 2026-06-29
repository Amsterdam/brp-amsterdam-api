import random
import re
import string

from azure.core.exceptions import AzureError
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from django.conf import settings
from django.core.management import BaseCommand, CommandError

from brp_amsterdam_api.bevragingen.clients import BrpVAdhocServiceClient
from brp_amsterdam_api.bevragingen.clients.brp_v import PasswordNotChanged

ENDPOINTS = {
    "personen": settings.BRP_PERSONEN_URL,
    "bewoningen": settings.BRP_BEWONINGEN_URL,
    "verblijf": settings.BRP_VERBLIJFPLAATSHISTORIE_URL,
}


class Command(BaseCommand):
    help = "Change the password for the BRP V Adhoc Service"

    def handle(self, *args, **options):
        password = _generate_password()

        # Make sure we've generated a valid password, if not, keep trying until we do.
        while len(_validate_password(password)) > 0:
            password = _generate_password()

        client = BrpVAdhocServiceClient(
            endpoint_url=settings.BRP_V_ADHOC_URL,
            user=settings.BRP_V_ADHOC_USER,
            password=settings.BRP_V_ADHOC_PASSWORD,
            cert_file=settings.BRP_MTLS_CERT_FILE,
            key_file=settings.BRP_MTLS_KEY_FILE,
        )

        try:
            client.change_password(password)
        except PasswordNotChanged as e:
            raise CommandError(str(e)) from e

        # If the password was successfully changed, we need to update the keyvault secrets.
        credential = DefaultAzureCredential(
            managed_identity_client_id=settings.MANAGED_IDENTITY_CLIENT_ID
        )
        secret_client = SecretClient(vault_url=settings.AZURE_KEYVAULT_URL, credential=credential)
        try:
            secret_client.set_secret("brp-v-adhoc-password", password)
        except AzureError as e:
            self.stdout.write(
                self.style.ERROR(
                    f"Password was changed to {password}, but failed to update the secret in"
                    " Azure Key Vault"
                )
            )
            raise CommandError(str(e)) from e

        self.stdout.write(
            self.style.SUCCESS("Successfully changed the password for the BRP V Adhoc Service")
        )


def _generate_password() -> str:
    """
    Generate a 16 character random password that adheres to the BRP password policy.
    """
    # For the remaining 7 characters, we can choose categories A B and C.
    all_characters = string.ascii_letters + string.digits + string.punctuation
    return "".join(random.choices(all_characters, k=16))


def _validate_password(password) -> list:
    """
    Validate the password to make sure it adheres to the BRP password policy.

    There are four categories of characters:
    - A: Letters a-z A-Z
    - B: Digits 0-9
    - C: Space
    - D: All other ASCII characters in decimal range 32 <= x < 127
    """

    errors = []

    # 1. A password should be 10 - 64 characters
    if not 10 <= len(password) <= 64:
        errors.append("[1] Password must be between 10 and 64 characters")

    # 2. Only extended ASCII characters are allowed
    ascii_codes = [ord(c) for c in password]
    if any(32 >= c > 126 for c in ascii_codes):
        errors.append("[2] Password can only contain ASCII characters between 32 <= x < 127")

    # 3. There should be no ascending or descending streaks of 4 characters, e.g. ABCD, 1234, zyxw
    if _find_consecutive_run(ascii_codes) >= 4:
        errors.append("[3] Password can't contain a ascending or descending range of 4 characters")

    """
    4. Password should contain at least 3 of the following rules:
    - At least one capital letter (A-Z)
    - At least one small letter (a-z)
    - At least one digit (0-9)
    - At least one special character (!)
    """

    rules = [
        bool(re.search(r"[A-Z]", password)),
        bool(re.search(r"[a-z]", password)),
        bool(re.search(r"\d", password)),
        bool(re.search(rf"[{re.escape(string.punctuation)}]", password)),
    ]
    if sum(rules) < 3:
        errors.append(
            "[4] Password should contain at least 3 of the following rules: "
            "at least one capital letter (A-Z), at least one small letter (a-z), "
            "at least one digit (0-9), at least one special character"
        )

    return errors


def _find_consecutive_run(values):
    """ "
    Find the longest consecutive run (asc or desc) in the given list of ascii values.

    For example:

    [1, 2, 3, 4, 6] -> 4
    [1, 2, 5, 3, 4, 5] -> 3
    [F, E, D, C, B, A] -> 6
    """
    if not values:
        return 0
    ascii_changes = [abs(c1 - c2) for c1, c2 in zip(values[:-1], values[1:])]

    current = 1
    longest = 1

    for change in ascii_changes:
        if change == 1:
            current += 1
        else:
            current = 1
        longest = max(longest, current)

    return longest
