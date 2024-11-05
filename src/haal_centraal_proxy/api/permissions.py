from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from functools import cached_property
from typing import ClassVar

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
      ``ParameterPolicy(default_scope={"required-scope", "scope2"})`` (shorthand:
      ``ParameterPolicy.for_all_values(...)``).
    * Require a scope to allow certain values:
      ``ParameterPolicy(scopes_for_values={"value1": {"required-scope", ...}, "value2": ...)``.
    * Require a scope, but allow a wildcard fallback:
      ``ParameterPolicy(scopes_for_values=..., default_scope=...)``
    """

    #: Singleton for convenience, to mark that the parameter is always allowed.
    #: This is the same as using `default_scope=set()`.
    allow_all: ClassVar[ParameterPolicy]

    #: A specific scope for each value.
    scopes_for_values: dict[str | None, set[str]] = field(default_factory=dict)

    #: A default scope in case the value is missing in the :attr:`scopes_for_values`.
    default_scope: set[str] | None = None

    @classmethod
    def for_all_values(cls, scopes_for_all_values: set[str]):
        """A configuration shorthand, to require a specific scope for all incoming values."""
        return cls(default_scope=scopes_for_all_values)

    def get_needed_scopes(self, value) -> set[str]:
        """Return which scopes are required for a given parameter value."""
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
):
    """Check the parameters of the query"""
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


def _validate_parameter_values(
    policy: ParameterPolicy,
    field_name: str,
    values: list | str,
    user_scopes: set[str],
    service_log_id: str,
):
    """Check whether the given parameter values are allowed."""
    is_multiple = isinstance(values, list)
    if not is_multiple:
        # Multiple values: will check each one
        values = [values]

    invalid_values = []
    denied_values = []
    all_needed_scopes = set()
    for value in values:
        try:
            needed_scopes = policy.get_needed_scopes(value)
        except ValueError:
            invalid_values.append(value)
        else:
            all_needed_scopes.update(needed_scopes)
            if not user_scopes.issuperset(needed_scopes):
                denied_values.append(value)

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
            code="permissionDenied",
            status=status.HTTP_403_FORBIDDEN,
        )

    return all_needed_scopes


class IsUserScope(BasePermission):
    """Permission check, wrapped in a DRF permissions adapter"""

    def __init__(self, needed_scopes):
        self.needed_scopes = frozenset(needed_scopes)

    def has_permission(self, request, view):
        """Check whether the user has all required scopes"""
        # This calls into 'authorization_django middleware':
        return request.is_authorized_for(*self.needed_scopes)

    def has_object_permission(self, request, view, obj):
        return self.has_permission(request, view)
