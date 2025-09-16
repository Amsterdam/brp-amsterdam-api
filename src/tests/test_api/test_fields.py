import pytest

from brp_amsterdam_api.bevragingen import fields
from brp_amsterdam_api.bevragingen.fields import compact_fields_values, read_dataset_fields_files


class TestReadConfiguration:
    def test_read_wildcard_no_match(self):
        """Prove that not having matches will be noticed."""
        with pytest.raises(FileNotFoundError):
            read_dataset_fields_files("non-existent/*.txt")

    def test_read_dataset_fields_files(self, tmp_path, monkeypatch):
        """Prove that the collection of fields can be properly read from the configuration."""
        dir = tmp_path.joinpath("dataset_fields")
        dir.mkdir()
        dir.joinpath("role1.txt").write_text("naam\nadres\nwoonplaats\n")
        dir.joinpath("role2.txt").write_text("adres\nwoonplaats\nkinderen\n")
        dir.joinpath("role3.txt").write_text("adres  # comment\n# woonplaats\n\nkinderen\n")

        monkeypatch.setattr(fields, "CONFIG_DIR", tmp_path)
        scopes_for_values = read_dataset_fields_files("dataset_fields/role*.txt")
        assert scopes_for_values == {
            "naam": {"role1"},
            "adres": {"role1", "role2", "role3"},
            "woonplaats": {"role1", "role2"},
            "kinderen": {"role2", "role3"},
        }


class TestCompactValues:

    def test_compact_fields_values(self):
        """Prove that wildcard values can be properly stripped from a list of allowed values."""
        assert compact_fields_values(
            [
                "naam.voornaam",
                "naam.*",
                "naam.achternaam",
                "adres",
            ]
        ) == ["naam", "adres"]

        assert compact_fields_values(["naam", "naamlanger"]) == ["naam", "naamlanger"]
        assert compact_fields_values(["naam.*", "naamlanger"]) == ["naam", "naamlanger"]
