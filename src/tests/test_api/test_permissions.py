import pytest

from brp_amsterdam_api.bevragingen.permissions import (
    AccessDenied,
    InvalidParameters,
    InvalidValues,
    ParameterPolicy,
    validate_parameters,
)


class TestParameterPolicy:
    """Test how the ParameterPolicy class works."""

    def test_get_needed_scopes(self):
        """Prove that the needed scopes are properly returned."""
        policy = ParameterPolicy(
            scopes_for_values={
                "naam": {"role-user", "role2"},
                "adres.*": {"role-adres"},
                "adres.label": {"role-user", "role2"},
            },
            default_scope={"default"},
        )
        assert policy.get_needed_scopes("naam") == {"role-user", "role2"}
        assert policy.get_needed_scopes("adres.label") == {"role-user", "role2"}
        assert policy.get_needed_scopes("adres.misc") == {"role-adres"}
        assert policy.get_needed_scopes("foobar") == {"default"}

    def test_no_default_scope(self):
        """Prove that a parameter is denied when there is no corresponding value."""
        policy = ParameterPolicy(
            scopes_for_values={
                "naam": {"role1"},
            }
        )
        assert policy.get_needed_scopes("naam") == {"role1"}
        with pytest.raises(ValueError, match="Value not handled: foobar"):
            policy.get_needed_scopes("foobar")

    def test_get_allowed_values(self):
        """Prove that get_allowed_values() returns expected results."""
        policy = ParameterPolicy(
            scopes_for_values={
                "naam.voornaam": {"dataset1"},
                "ouders": {"dataset1"},
                "kinderen.naam": {"dataset1", "dataset2"},
                "other": {"dataset3"},
                "none": None,
                "always": set(),
            }
        )
        assert policy.get_allowed_values({"dataset1"}) == [
            "naam.voornaam",
            "ouders",
            "kinderen.naam",
            "always",
        ]
        assert policy.get_allowed_values({"dataset2"}) == ["kinderen.naam", "always"]
        assert policy.get_allowed_values({"dataset3"}) == ["other", "always"]
        assert policy.get_allowed_values({"datasetFOO"}) == ["always"]


class TestValidateParameters:
    """Test how the request is checked and transformed."""

    RULESET = {
        "type": ParameterPolicy(
            scopes_for_values={
                # Require a scope for this value
                "RaadpleegMetBurgerservicenummer": {"benk-brp-zoekvraag-bsn"},
                "ZoekMetPostcodeEnHuisnummer": {"benk-brp-zoekvraag-postcode-huisnummer"},
            }
        ),
        "fields": ParameterPolicy(
            scopes_for_values={
                "naam": set(),  # allow all.
                "ouders": None,  # no role defined!
                "adressering": {"BRP/adres-buitenland"},  # require a scope for using this value
                "kinderen.naam": {"dataset1", "dataset2", "dataset3"},
            }
        ),
        "gemeenteVanInschrijving": ParameterPolicy(
            {"0363": set()},  # ok to include ?gemeenteVanInschrijving=0363
            default_scope={"benk-brp-landelijk"},  # Require a scope for unknown values
        ),
    }

    def test_unknown_key(self, caplog):
        """Prove that only known fields are accepted."""
        with pytest.raises(InvalidParameters, match="foobar") as exc_info:
            validate_parameters(
                ruleset=self.RULESET,
                hc_request={
                    "type": "RaadpleegMetBurgerservicenummer",
                    "foobar": "XYZ",
                },
                user_scopes={"benk-brp-zoekvraag-bsn"},
            )
        assert exc_info.value.invalid_names == ["foobar"]
        assert not caplog.messages

    def test_unknown_value_type(self):
        """Prove that only known values are accepted."""
        with pytest.raises(InvalidValues, match="FooBar") as exc_info:
            validate_parameters(
                ruleset=self.RULESET,
                hc_request={"type": "FooBar"},
                user_scopes=set(),
            )
        assert exc_info.value.field_name == "type"
        assert exc_info.value.invalid_values == ["FooBar"]

    def test_unknown_value_fields(self):
        """Prove that only known values are accepted.
        This isn't checked with the "type" argument as that is special/mandatory.
        """
        with pytest.raises(InvalidValues, match="FooBar") as exc_info:
            validate_parameters(
                ruleset=self.RULESET,
                hc_request={
                    "type": "RaadpleegMetBurgerservicenummer",
                    "fields": ["FooBar"],
                },
                user_scopes={"benk-brp-zoekvraag-bsn"},
            )
        assert exc_info.value.field_name == "fields"
        assert exc_info.value.invalid_values == ["FooBar"]

    def test_value_scope_check(self):
        """Prove that 'type' field is checked for authorization."""
        with pytest.raises(AccessDenied, match="ZoekMetPostcodeEnHuisnummer") as exc_info:
            validate_parameters(
                ruleset=self.RULESET,
                hc_request={"type": "ZoekMetPostcodeEnHuisnummer"},
                user_scopes=set(),
            )

        assert exc_info.value.field_name == "type"
        assert exc_info.value.denied_values == ["ZoekMetPostcodeEnHuisnummer"]
        assert exc_info.value.needed_scopes == {"benk-brp-zoekvraag-postcode-huisnummer"}

    def test_deny_other_gemeente(self):
        """Prove that search outside Amsterdam is denied."""
        with pytest.raises(AccessDenied, match="gemeenteVanInschrijving") as exc_info:
            validate_parameters(
                ruleset=self.RULESET,
                hc_request={
                    "type": "RaadpleegMetBurgerservicenummer",
                    "fields": ["naam"],
                    "gemeenteVanInschrijving": "0111",
                },
                user_scopes={"benk-brp-zoekvraag-bsn"},
            )
        assert exc_info.value.field_name == "gemeenteVanInschrijving"
        assert exc_info.value.denied_values == ["0111"]
        assert exc_info.value.needed_scopes == {"benk-brp-landelijk"}

    def test_deny_field_access(self):
        """Prove that requesting certain fields is not possible without extra permissions."""
        with pytest.raises(AccessDenied, match="adressering") as exc_info:
            validate_parameters(
                ruleset=self.RULESET,
                hc_request={
                    "type": "ZoekMetPostcodeEnHuisnummer",
                    "fields": ["adressering"],
                },
                user_scopes={"benk-brp-zoekvraag-postcode-huisnummer"},
            )
        assert exc_info.value.field_name == "fields"
        assert exc_info.value.denied_values == ["adressering"]
        assert exc_info.value.needed_scopes == {"BRP/adres-buitenland"}

    def test_multiple_scopes(self):
        """Prove that only one scope is needed for the value."""
        needed = validate_parameters(
            ruleset=self.RULESET,
            hc_request={
                "type": "ZoekMetPostcodeEnHuisnummer",
                "fields": ["kinderen.naam"],
            },
            user_scopes={"benk-brp-zoekvraag-postcode-huisnummer", "dataset2"},
        )
        assert needed == {
            "benk-brp-zoekvraag-postcode-huisnummer",
            "dataset2",
        }

    def test_no_scopes_defined(self):
        """Prove that having "None" as parameter value means no scopes are defined."""
        with pytest.raises(AccessDenied, match="ouders") as exc_info:
            validate_parameters(
                ruleset=self.RULESET,
                hc_request={
                    "type": "ZoekMetPostcodeEnHuisnummer",
                    "fields": ["ouders"],
                },
                user_scopes={"benk-brp-zoekvraag-postcode-huisnummer"},
            )

        assert exc_info.value.field_name == "fields"
        assert exc_info.value.denied_values == ["ouders"]
        assert exc_info.value.needed_scopes == {"<always deny fields=ouders>"}

    def test_satisfy_all_scopes(self):
        """Prove that access is given when all scopes are satisfied."""
        needed = validate_parameters(
            ruleset=self.RULESET,
            hc_request={
                "type": "ZoekMetPostcodeEnHuisnummer",
                "fields": ["naam", "adressering", "kinderen.naam"],
                "gemeenteVanInschrijving": "0363",
            },
            user_scopes={
                "benk-brp-zoekvraag-postcode-huisnummer",  # type OK
                "dataset2",  # fields ok
                "BRP/adres-buitenland",  # gemeenteVanInschrijving ok
            },
        )
        assert needed == {
            "benk-brp-zoekvraag-postcode-huisnummer",
            "dataset2",
            "BRP/adres-buitenland",
        }
