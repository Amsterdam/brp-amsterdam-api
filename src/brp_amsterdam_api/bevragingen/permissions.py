from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from functools import cached_property
from typing import ClassVar

from rest_framework.permissions import BasePermission

logger = logging.getLogger(__name__)
audit_log = logging.getLogger("brp_amsterdam_api.audit")


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

    #: Singleton for convenience, to mark that a value is always allowed.
    allow_value: ClassVar[set]

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

    def get_allowed_values(self, user_scopes: set[str]) -> list[str]:
        """Tell which values are allowed according to the given scope.
        This may include values that end with a wildcard expression.
        """
        return [
            value
            for value, required_scope in self.scopes_for_values.items()
            if (
                # None is permission denied, empty set is no permissions required
                required_scope is not None
                and (not required_scope or not required_scope.isdisjoint(user_scopes))
            )
        ]

    @cached_property
    def _roles_for_values_re(self) -> list[tuple[re.Pattern, set[str]]]:
        return [
            (re.compile(re.escape(key).replace(r"\*", ".+")), roles)
            for key, roles in self.scopes_for_values.items()
            if key.endswith("*")
        ]

    def validate_values(
        self, field_name: str, values: list | str, user_scopes: set[str]
    ) -> set[str]:
        """Check whether the given parameter values are allowed.

        :param field_name: The field being checked
        :param values: The values parsed for the field.
        :param user_scopes: Granted scopes of the current user.
        :raises AccessDenied: When the user should be denied
        :raises ProblemJsonException: When the value is not supported.
        :returns: The scopes that were used to access.
        """
        # Multiple values: will check each one
        values = [values] if not isinstance(values, list) else values
        invalid_values = []
        denied_values = []
        all_needed_scopes = set()
        for value in values:
            try:
                needed_scopes = self.get_needed_scopes(value)
            except ValueError:
                invalid_values.append(str(value))
                continue

            if needed_scopes is None:
                # No scopes defined for this value. Deny.
                denied_values.append(value)
                all_needed_scopes.add(f"<always deny {field_name}={value}>")
            elif needed_scopes:
                # Not empty set, user must have ONE of these.
                if user_scopes.isdisjoint(needed_scopes):  # OR comparison
                    # User doesn't have it.
                    denied_values.append(value)

                    # track for logging
                    if len(needed_scopes) > 1:
                        log_needed = sorted(needed_scopes)
                        if len(needed_scopes) > 3:
                            log_needed = log_needed[:2] + ["..."]
                        all_needed_scopes.add("|".join(log_needed))
                    else:
                        all_needed_scopes.update(needed_scopes)
                else:
                    # Track for logging, but reduce to what the user already has.
                    # This makes sure the "needed" list doesn't show all alternative options.
                    all_needed_scopes.update(needed_scopes & user_scopes)

        if invalid_values:
            raise InvalidValues(field_name, invalid_values)

        if denied_values:
            raise AccessDenied(
                field_name=field_name,
                denied_values=denied_values,
                needed_scopes=all_needed_scopes,
            )

        return all_needed_scopes


ParameterPolicy.allow_all = ParameterPolicy(default_scope=set())
ParameterPolicy.allow_value = frozenset()


class AccessDenied(Exception):
    """Raise that access is denied, passing all relevant bits"""

    def __init__(
        self,
        field_name: str,
        denied_values: list[str],
        needed_scopes: set[str],
    ):
        super().__init__(f"Access denied for {field_name}={','.join(denied_values)}")
        self.needed_scopes = needed_scopes
        self.field_name = field_name
        self.denied_values = denied_values


class InvalidParameters(Exception):
    """Raise that invalid values are provided."""

    def __init__(self, invalid_names: list[str]):
        super().__init__(f"Invalid parameters: {','.join(invalid_names)}")
        self.invalid_names = invalid_names


class InvalidValues(Exception):
    """Raise that invalid values are provided."""

    def __init__(self, field_name: str, invalid_values: list[str]):
        super().__init__(f"Invalid values for {field_name}={','.join(invalid_values)}")
        self.field_name = field_name
        self.invalid_values = invalid_values


def validate_parameters(
    ruleset: dict[str, ParameterPolicy],
    hc_request: dict,
    user_scopes: set[str],
) -> set[str]:
    """Validate the incoming request against the ruleset of allowed parameters/values.

    When access is denied, this will raise an exception that returns the desired error response.
    Both grants/denies are logged to the audit log as well.

    :param ruleset: The ruleset that defines which scopes are required for certain parameters.
    :param hc_request: The request that will be validated.
    :param user_scopes: The scopes that this user has access to.
    :param service_log_id: Which service is being accessed (used to improve log messages)
    :param base_validated_scopes: Which scopes are already validated (used to improve log messages)
    :raises ProblemJsonException: When parameters are missing, or values are invalid.
    :returns: The needed scopes needed to satisfy the request.
    """
    request_type = hc_request.get("type")
    if not request_type:
        raise InvalidParameters(["type"])

    # Check whether certain parameters are allowed:
    invalid_names = []
    all_needed_scopes = set()
    for field_name, values in hc_request.items():
        try:
            policy = ruleset[field_name]
        except KeyError:
            invalid_names.append(field_name)
        else:
            needed_for_param = policy.validate_values(field_name, values, user_scopes)
            all_needed_scopes.update(needed_for_param)

    if invalid_names:
        raise InvalidParameters(invalid_names)

    return all_needed_scopes


class IsUserScope(BasePermission):
    """Permission check, wrapped in a DRF permissions adapter"""

    message = "Required scopes not given in token."
    code = "permissionDenied"

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
        missing = sorted(self.needed_scopes - user_scopes)
        appid = request.get_token_claims.get("appid") if request.get_token_claims else None
        audit_log.info(
            "Denied overall access to '%(path)s', missing %(missing)s",
            {"path": request.path, "missing": ",".join(missing)},
            extra={
                "path": request.path,
                "user": request.headers.get("X-User", None),
                "correlationId": request.headers.get("X-Correlation-ID", None),
                "taskDescription": request.headers.get("X-Task-Description", None),
                "granted": sorted(user_scopes),
                "needed": sorted(self.needed_scopes),
                "missing": missing,
                "appid": appid,
            },
        )

        return request.is_authorized_for(*self.needed_scopes)

    def has_object_permission(self, request, view, obj):
        return self.has_permission(request, view)


class HasRequiredHeaders(BasePermission):
    """Permission check to check whether expected headers are present."""

    required_headers = ("X-User", "X-Correlation-ID", "X-Task-Description")
    message = f"The following headers are required: {', '.join(required_headers)}."
    code = "missingHeaders"  # this helps both clients and unittest to see the difference.

    def has_permission(self, request, view):
        return all(request.headers.get(header) for header in self.required_headers)

    def has_object_permission(self, request, view, obj):
        return self.has_permission(request, view)
