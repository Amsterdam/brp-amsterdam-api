from __future__ import annotations

import logging
import pathlib
import re
from collections import defaultdict

from django.conf import settings

logger = logging.getLogger(__name__)

CONFIG_DIR: pathlib.Path = settings.SRC_DIR / "config"


def read_dataset_fields_files(file_glob, accepted_field_names: set[str] | None = None) -> dict:
    """Read the 'gegevensset' configuration files.
    The scopes are grouped by field name they allow.

    Comments and whitespace are allowed.
    :returns: Which field names (keys) are accessible for which roles (values).
    """
    scopes_for_values = defaultdict(set)
    files = list(CONFIG_DIR.glob(file_glob))
    if not files:
        raise FileNotFoundError(file_glob)

    for file in files:
        scope_name = file.stem
        for field_name in _read_file(file):
            if accepted_field_names and field_name.removesuffix(".*") not in accepted_field_names:
                logger.warning(
                    "Configuration %s lists unknown field: %s",
                    file.relative_to(CONFIG_DIR),
                    field_name,
                )
                continue

            scopes_for_values[field_name].add(scope_name)

    return dict(scopes_for_values)


def read_config(file_name) -> set[str]:
    """Read a configuration file, remove comments and whitespace."""
    return set(_read_file(CONFIG_DIR / file_name))


def _read_file(file: pathlib.Path) -> list[str]:
    """Remove comments, newlines and empty lines from the configuration files"""
    return [
        line
        for field_name in file.read_text().splitlines()
        if (line := field_name.partition("#")[0].strip())
    ]


def compact_fields_values(allowed_values: list[str]):
    """Determine what the "fields" parameter should be if it's not given in request.

    By default, it will allow all possible field to be returned that a user has access to.
    """
    if not allowed_values:
        raise ValueError("No allowed values given")

    # Remove wildcard versions (e.g. remove 'naam.voornaam' when 'naam.*' is also allowed).
    wildcards = [re.sub(r"\.?\*$", "", value) for value in allowed_values if value.endswith("*")]
    if not wildcards:
        return allowed_values

    is_wildcard_replaced = re.compile(
        "^({})".format(
            "|".join(
                re.escape(key).replace(r"\*", ".+") for key in allowed_values if key.endswith("*")
            )
        )
    )
    return [v for v in wildcards + allowed_values if not is_wildcard_replaced.match(v)]
