import pytest
from haal_centraal_proxy.api.exceptions import ProblemJsonException
from haal_centraal_proxy.api.permissions import (
    ParameterPolicy,
    read_dataset_fields_files,
    validate_parameters,
)


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
            default_scope={"BRP/buiten-gemeente"},  # Require a scope for unknown values
        ),
    }

    def test_unknown_key(self, caplog):
        """Prove that only known fields are accepted."""
        with pytest.raises(ProblemJsonException, match="foobar") as exc_info:
            validate_parameters(
                ruleset=self.RULESET,
                hc_request={
                    "type": "RaadpleegMetBurgerservicenummer",
                    "foobar": "XYZ",
                },
                user_scopes={"benk-brp-zoekvraag-bsn"},
                service_log_id="personen",
            )
        assert exc_info.value.detail == "De foutieve parameter(s) zijn: foobar."
        assert not caplog.messages

    def test_unknown_value_type(self, caplog):
        """Prove that only known values are accepted."""
        with pytest.raises(ProblemJsonException, match="FooBar") as exc_info:
            validate_parameters(
                ruleset=self.RULESET,
                hc_request={"type": "FooBar"},
                user_scopes=set(),
                service_log_id="personen",
            )
        assert exc_info.value.detail == "Het veld 'type' ondersteund niet de waarde(s): FooBar."
        assert not caplog.messages

    def test_unknown_value_fields(self, caplog):
        """Prove that only known values are accepted.
        This isn't checked with the "type" argument as that is special/mandatory.
        """
        with pytest.raises(ProblemJsonException, match="FooBar") as exc_info:
            validate_parameters(
                ruleset=self.RULESET,
                hc_request={
                    "type": "RaadpleegMetBurgerservicenummer",
                    "fields": ["FooBar"],
                },
                user_scopes={"benk-brp-zoekvraag-bsn"},
                service_log_id="personen",
            )
        assert exc_info.value.detail == "Het veld 'fields' ondersteund niet de waarde(s): FooBar."
        assert not caplog.messages

    def test_value_scope_check(self, caplog):
        """Prove that 'type' field is checked for authorization."""
        with pytest.raises(ProblemJsonException, match="ZoekMetPostcodeEnHuisnummer"):
            validate_parameters(
                ruleset=self.RULESET,
                hc_request={"type": "ZoekMetPostcodeEnHuisnummer"},
                user_scopes=set(),
                service_log_id="personen",
            )
        assert caplog.messages[0] == (
            "Denied access to 'personen' using type=ZoekMetPostcodeEnHuisnummer, "
            "missing benk-brp-zoekvraag-postcode-huisnummer"
        )

    def test_deny_other_gemeente(self, caplog):
        """Prove that search outside Amsterdam is denied."""
        with pytest.raises(ProblemJsonException, match="gemeenteVanInschrijving"):
            validate_parameters(
                ruleset=self.RULESET,
                hc_request={
                    "type": "RaadpleegMetBurgerservicenummer",
                    "fields": ["naam"],
                    "gemeenteVanInschrijving": "0111",
                },
                user_scopes={"benk-brp-zoekvraag-bsn"},
                service_log_id="personen",
            )
        assert caplog.messages[0] == (
            "Denied access to 'personen' using gemeenteVanInschrijving=0111, "
            "missing BRP/buiten-gemeente"
        )

    def test_deny_field_access(self, caplog):
        """Prove that requesting certain fields is not possible without extra permissions."""
        with pytest.raises(ProblemJsonException, match="adressering"):
            validate_parameters(
                ruleset=self.RULESET,
                hc_request={
                    "type": "ZoekMetPostcodeEnHuisnummer",
                    "fields": ["adressering"],
                },
                user_scopes={"benk-brp-zoekvraag-postcode-huisnummer"},
                service_log_id="personen",
            )
        assert caplog.messages[0] == (
            "Denied access to 'personen' using fields=adressering, missing BRP/adres-buitenland"
        )

    def test_multiple_scopes(self):
        """Prove that only one scope is needed for the value."""
        needed = validate_parameters(
            ruleset=self.RULESET,
            hc_request={
                "type": "ZoekMetPostcodeEnHuisnummer",
                "fields": ["kinderen.naam"],
            },
            user_scopes={"benk-brp-zoekvraag-postcode-huisnummer", "dataset2"},
            service_log_id="personen",
        )
        assert needed == {"benk-brp-zoekvraag-postcode-huisnummer", "dataset1|dataset2|..."}

    def test_no_scopes_defined(self, caplog):
        """Prove that having "None" as parameter value means no scopes are defined."""
        with pytest.raises(ProblemJsonException, match="ouders"):
            validate_parameters(
                ruleset=self.RULESET,
                hc_request={
                    "type": "ZoekMetPostcodeEnHuisnummer",
                    "fields": ["ouders"],
                },
                user_scopes={"benk-brp-zoekvraag-postcode-huisnummer"},
                service_log_id="personen",
            )
        assert caplog.messages[0] == (
            "Denied access to 'personen' using fields=ouders, missing <undefined fields=ouders>"
        )
        assert caplog.records[0].args == {
            "service": "personen",
            "field": "fields",
            "values": "ouders",
            "missing": "<undefined fields=ouders>",
        }

    def test_satisfy_all_scopes(self):
        """Prove ."""
        needed = validate_parameters(
            ruleset=self.RULESET,
            hc_request={
                "type": "ZoekMetPostcodeEnHuisnummer",
                "fields": ["naam", "adressering", "kinderen.naam"],
                "gemeenteVanInschrijving": "0363",
            },
            user_scopes={
                "benk-brp-zoekvraag-postcode-huisnummer",
                "dataset2",
                "BRP/adres-buitenland",
            },
            service_log_id="personen",
        )
        assert needed == {
            "benk-brp-zoekvraag-postcode-huisnummer",
            "dataset1|dataset2|...",
            "BRP/adres-buitenland",
        }


class TestReadConfiguration:
    def test_read_dataset_fields_files(self, tmp_path, settings):
        """Prove that the collection of fields can be properly read from the configuration."""
        dir = tmp_path.joinpath("dataset_fields")
        dir.mkdir()
        dir.joinpath("role1.txt").write_text("naam\nadres\nwoonplaats\n")
        dir.joinpath("role2.txt").write_text("adres\nwoonplaats\nkinderen\n")
        dir.joinpath("role3.txt").write_text("adres  # comment\n# woonplaats\n\nkinderen\n")

        settings.SRC_DIR = tmp_path
        scopes_for_values = read_dataset_fields_files("dataset_fields/role*.txt")
        assert scopes_for_values == {
            "naam": {"role1"},
            "adres": {"role1", "role2", "role3"},
            "woonplaats": {"role1", "role2"},
            "kinderen": {"role2", "role3"},
        }
