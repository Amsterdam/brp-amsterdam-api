from __future__ import annotations

import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from functools import cached_property
from typing import ClassVar

from django.conf import settings
from rest_framework import status
from rest_framework.permissions import BasePermission

from .exceptions import ProblemJsonException

audit_log = logging.getLogger("haal_centraal_proxy.audit")


@dataclass
class ParameterPolicy:
    """A rule for which parameter values are allowed.

    Each combination of a parameter-value can require a specific role.
    When the `set` object is left empty, it's treated as not requiring any scope.

    This allows to code the following variations:

    * Allow the parameter, and ALL values:
      ``ParameterPolicy(default_scope=set())`` (shorthand: ``ParameterPolicy.allow_all``).
    * Require that certain scopes are fulfilled:
      ``ParameterPolicy(default_scope={"required-scope", "alternative-scope2"})``
      (shorthand: ``ParameterPolicy.for_all_values(...)``).
    * Require a scope to allow certain values:
      ``ParameterPolicy(scopes_for_values={"value1": {"required-scope", ...}, "value2": ...})``.
    * Require a scope, but allow a wildcard fallback:
      ``ParameterPolicy(scopes_for_values=..., default_scope=...)``
    """

    #: Singleton for convenience, to mark that the parameter is always allowed.
    #: This is the same as using `default_scope=set()`.
    allow_all: ClassVar[ParameterPolicy]

    #: A specific scope for each value. Multiple values acts as OR.
    #: The user needs to have one of the listed scopes.
    scopes_for_values: dict[str | None, set[str] | None] = field(default_factory=dict)

    #: A default scope in case the value is missing in the :attr:`scopes_for_values`.
    default_scope: set[str] | None = None

    @classmethod
    def for_all_values(cls, scopes_for_all_values: set[str]):
        """A configuration shorthand, to require a specific scope for all incoming values."""
        return cls(default_scope=scopes_for_all_values)

    def get_needed_scopes(self, value) -> set[str] | None:
        """Return which scopes are required for a given parameter value.
        The user only needs to have one scope of the set ("OR" comparison).
        """
        try:
            return self.scopes_for_values[value]
        except KeyError:
            # Check if there is a "fieldvalue*" lookup
            for pattern, roles in self._roles_for_values_re:
                if pattern.match(value):
                    return roles

        if self.default_scope is None:
            raise ValueError(f"Value not handled: {value}")
        return self.default_scope

    @cached_property
    def _roles_for_values_re(self) -> list[tuple[re.Pattern, set[str]]]:
        return [
            (re.compile(re.escape(key).replace(r"\*", ".+")), roles)
            for key, roles in self.scopes_for_values.items()
            if key.endswith("*")
        ]


ParameterPolicy.allow_all = ParameterPolicy(default_scope=set())


def validate_parameters(
    ruleset: dict[str, ParameterPolicy],
    hc_request,
    user_scopes: set[str],
    *,
    service_log_id: str,
) -> set[str]:
    """Validate the incoming request against the ruleset of allowed parameters/values.

    When access is denied, this will raise an exception that returns the desired error response.
    Both grants/denies are logged to the audit log as well.

    :returns: The needed scopes needed to satify the request.
    """
    request_type = hc_request.get("type")
    if not request_type:
        raise ProblemJsonException(
            title="Een of meerdere parameters zijn niet correct.",
            status=400,
            detail="De foutieve parameter(s) zijn: types.",
            code="paramsValidation",
        )

    # Check whether certain parameters are allowed:
    invalid_names = []
    all_needed_scopes = set()
    for field_name, values in hc_request.items():
        try:
            policy = ruleset[field_name]
        except KeyError:
            invalid_names.append(field_name)
        else:
            needed_for_param = _validate_parameter_values(
                policy, field_name, values, user_scopes, service_log_id=service_log_id
            )
            all_needed_scopes.update(needed_for_param)

    if invalid_names:
        raise ProblemJsonException(
            title="Een of meerdere parameters zijn niet correct.",
            detail=f"De foutieve parameter(s) zijn: {', '.join(invalid_names)}.",
            code="paramsValidation",
            status=status.HTTP_400_BAD_REQUEST,
        )

    audit_log.info(
        "Granted access for %(service)s.%(type)s, needed: %(needed)s, granted: %(granted)s",
        {
            "service": service_log_id,
            "type": request_type,
            "needed": ",".join(sorted(all_needed_scopes)),
            "granted": ",".join(sorted(user_scopes)),
        },
        extra={
            "service": service_log_id,
            "type": request_type,
            "needed": sorted(all_needed_scopes),
            "granted": sorted(user_scopes),
        },
    )
    return all_needed_scopes


def _validate_parameter_values(
    policy: ParameterPolicy,
    field_name: str,
    values: list | str,
    user_scopes: set[str],
    service_log_id: str,
):
    """Check whether the given parameter values are allowed."""
    # Multiple values: will check each one
    values = [values] if not isinstance(values, list) else values
    invalid_values = []
    denied_values = []
    all_needed_scopes = set()
    for value in values:
        try:
            needed_scopes = policy.get_needed_scopes(value)
        except ValueError:
            invalid_values.append(value)
        else:
            if needed_scopes is None:
                # No scopes defined for this value. Deny.
                denied_values.append(value)
                all_needed_scopes.add(f"<undefined {field_name}={value}>")
            elif needed_scopes:
                if user_scopes.isdisjoint(needed_scopes):  # OR comparison
                    denied_values.append(value)

                # track for logging
                log_needed = sorted(needed_scopes)
                if len(needed_scopes) > 2:
                    log_needed = log_needed[:2] + ["..."]
                all_needed_scopes.add("|".join(log_needed))

    if invalid_values:
        raise ProblemJsonException(
            title="Een of meerdere veldnamen zijn niet correct.",
            detail=(
                f"Het veld '{field_name}' ondersteund niet"
                f" de waarde(s): {', '.join(invalid_values)}."
            ),
            code="paramsValidation",
            status=status.HTTP_400_BAD_REQUEST,
        )

    if denied_values:
        audit_log.info(
            "Denied access to '%(service)s' using %(field)s=%(values)s, missing %(missing)s",
            {
                "service": service_log_id,
                "field": field_name,
                "values": ",".join(denied_values),
                "missing": ",".join(sorted(all_needed_scopes - user_scopes)),
            },
            extra={
                "service": service_log_id,
                "field": field_name,
                "values": denied_values,
                "granted": sorted(user_scopes),
                "needed": sorted(all_needed_scopes),
            },
        )
        raise ProblemJsonException(
            title="U bent niet geautoriseerd voor deze operatie.",
            detail=f"U bent niet geautoriseerd voor {field_name} = {', '.join(denied_values)}.",
            code="permissionDenied",  # Same as what Haal Centraal would do.
            status=status.HTTP_403_FORBIDDEN,
        )

    return all_needed_scopes


class IsUserScope(BasePermission):
    """Permission check, wrapped in a DRF permissions adapter"""

    def __init__(self, needed_scopes):
        self.needed_scopes = frozenset(needed_scopes)

    def has_permission(self, request, view):
        """Check whether the user has all required scopes"""
        # When the access is granted, this skips going into the authorization middleware.
        # This is solely done to avoid incorrect log messages of "access granted",
        # because additional checks may still deny access.
        user_scopes = set(request.get_token_scopes)
        if user_scopes.issuperset(self.needed_scopes):
            return True

        # This calls into 'authorization_django middleware',
        # and logs when the access wasn't granted.
        return request.is_authorized_for(*self.needed_scopes)

    def has_object_permission(self, request, view, obj):
        return self.has_permission(request, view)


def read_dataset_fields_files(file_glob) -> dict:
    """Read the 'gegevensset' configuration files.
    The scopes are grouped by field name they allow.

    Comments and whitespace are allowed.
    :returns: Which field names (keys) are accessible for which roles (values).
    """
    scopes_for_values = defaultdict(set)
    files = settings.SRC_DIR.glob(file_glob)
    if not files:
        raise FileNotFoundError(file_glob)

    for file in files:
        scope_name = file.stem
        with open(file) as f:
            for field_name in f.readlines():
                # Strip comment or \n characters
                field_name = field_name.partition("#")[0].strip()
                if field_name:
                    scopes_for_values[field_name].add(scope_name)

    return dict(scopes_for_values)
