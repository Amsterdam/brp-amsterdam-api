import socket
import ssl
import threading

import pytest

from brp_amsterdam_api.bevragingen.clients import base
from brp_amsterdam_api.bevragingen.clients.base import BaseBrpClient
from brp_amsterdam_api.bevragingen.clients.brp_v import (
    _clean_empty_dicts,
    _derive_date_fields,
    _derive_under_investigation,
    _derive_values,
    _get_fields_by_category,
)


class TestBrpVAdhocServiceClient:

    def test_derive_initials(self):
        data = {"naam": {"voornamen": "Jan-Willem Hendrikus"}}
        _derive_values(data)
        assert data["naam"]["voorletters"] == "J.H."

    def test_derive_city(self):
        data = {"geboorte": {"plaats": {"code": "0363"}}}
        _derive_values(data)
        assert data["geboorte"]["plaats"]["omschrijving"] == "Amsterdam"

    def test_derive_country(self):
        data = {"geboorte": {"land": {"code": "6030"}}}
        _derive_values(data)
        assert data["geboorte"]["land"]["omschrijving"] == "Nederland"

    def test_derive_reason_dissolution(self):
        data = {"ontbindingHuwelijkPartnerschap": {"reden": {"code": "S"}}}
        _derive_values(data)
        assert (
            data["ontbindingHuwelijkPartnerschap"]["reden"]["omschrijving"]
            == "echtsch of huw.ontb na sch van tfl en bed/eindigen partnersch door ovk of ontb"
        )

    def test_derive_dates(self):
        data = {"geboorte": {"datum": "19700420"}}
        _derive_date_fields(data)
        assert data["geboorte"]["datum"] == {
            "datum": "1970-04-20",
            "type": "Datum",
            "langFormaat": "20 april 1970",
        }

    @pytest.mark.parametrize(
        "source_value, expected",
        [
            (
                "19650000",
                {
                    "datum": "1965-00-00",
                    "type": "Datum",
                    "langFormaat": "1965",
                },
            ),
            (
                "19650400",
                {
                    "datum": "1965-04-00",
                    "type": "Datum",
                    "langFormaat": "april 1965",
                },
            ),
        ],
    )
    def test_derive_partial_dates(self, source_value, expected):
        data = {"geboorte": {"datum": source_value}}
        _derive_date_fields(data)
        assert data["geboorte"]["datum"] == expected

    @pytest.mark.parametrize(
        "value, expected",
        [
            (
                "050620",
                {
                    "extra": {"inOnderzoek": "050620"},
                    "aangaanHuwelijkPartnerschap": {"inOnderzoek": {"plaats": True}},
                },
            ),
        ],
    )
    def test_derive_under_investigation(self, value, expected):
        data = {"extra": {"inOnderzoek": value}}
        _derive_under_investigation(data)
        assert data == expected

    def test_get_fields_by_category(self):
        assert _get_fields_by_category(5, 2, 10) == ["naam.voornamen"]
        assert _get_fields_by_category(5, 2, 0) == [
            "naam.voornamen",
            "naam.adellijkeTitelPredicaat",
            "naam.voorvoegsel",
            "naam.geslachtsnaam",
        ]
        assert _get_fields_by_category(7, 0, 0) == []

    def test_clean_empty_dicts(self):
        data = {
            "field1": {
                "subfield1": "value1",
                "subfield2": {},
                "subfield3": "",
                "subfield4": None,
            },
            "field2": {},
        }
        assert _clean_empty_dicts(data) == {
            "field1": {
                "subfield1": "value1",
                "subfield3": "",
                "subfield4": None,
            },
        }


class TestPQCTLS:
    """Tests for the opt-in hybrid ML-KEM TLS adapter (BRP_ENABLE_PQC_TLS)."""

    def setup_method(self):
        base._pqc_tls_status_logged = False

    def test_disabled_by_default(self, monkeypatch):
        monkeypatch.delenv("BRP_ENABLE_PQC_TLS", raising=False)
        client = BaseBrpClient("https://example.test")
        adapter = client._session.get_adapter("https://example.test")
        assert not isinstance(adapter, base._PQCTLSAdapter)

    def test_enabled_mounts_adapter_or_logs_fallback(self, monkeypatch, caplog):
        monkeypatch.setenv("BRP_ENABLE_PQC_TLS", "true")
        client = BaseBrpClient("https://example.test")
        adapter = client._session.get_adapter("https://example.test")

        if ssl.OPENSSL_VERSION_INFO >= (3, 5):
            assert isinstance(adapter, base._PQCTLSAdapter)
        else:
            assert not isinstance(adapter, base._PQCTLSAdapter)
            assert "falling back to classical TLS" in caplog.text

    @pytest.mark.skipif(
        ssl.OPENSSL_VERSION_INFO[:2] < (3, 5),
        reason="Hybrid ML-KEM TLS groups require OpenSSL >= 3.5",
    )
    def test_hybrid_group_negotiates_real_handshake(self, monkeypatch):
        """Proves the PQC context is real and completes a handshake, not inert config."""
        monkeypatch.setenv("BRP_ENABLE_PQC_TLS", "true")

        # On OpenSSL >= 3.5 a plain server context also defaults to preferring
        # the hybrid group, so both ends negotiate it without extra configuration.
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(*_generate_self_signed_cert())

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        host, port = sock.getsockname()

        def serve_once():
            conn, _ = sock.accept()
            with server_context.wrap_socket(conn, server_side=True) as tls_conn:
                tls_conn.recv(1)
            sock.close()

        thread = threading.Thread(target=serve_once, daemon=True)
        thread.start()

        pqc_context = base._build_pqc_ssl_context()
        pqc_context.check_hostname = False
        pqc_context.verify_mode = ssl.CERT_NONE
        raw_sock = socket.create_connection((host, port), timeout=5)
        with pqc_context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            tls_sock.send(b"x")
        thread.join(timeout=5)


def _generate_self_signed_cert():
    """Generate a throwaway self-signed cert/key pair for the loopback TLS test."""
    import datetime
    import ipaddress
    import tempfile

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.UTC))
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=5))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as cert_file:
        cert_file.write(cert.public_bytes(serialization.Encoding.PEM))

    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as key_file:
        key_file.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )

    return cert_file.name, key_file.name
