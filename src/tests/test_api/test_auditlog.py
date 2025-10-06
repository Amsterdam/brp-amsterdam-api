import logging
from unittest.mock import ANY, patch

import pytest
from azure.core.exceptions import HttpResponseError
from django.urls import reverse

from brp_amsterdam_api.bevragingen.loghandler import (
    AuditLogResponseError,
    BRPAuditLogHandler,
)
from brp_amsterdam_api.bevragingen.views.base import audit_log
from brp_amsterdam_api.settings import CustomJsonFormatter
from tests.utils import build_jwt_token


class TestAuditLogHandler:
    RESPONSE_POSTCODE_HUISNUMMER = {
        "type": "ZoekMetPostcodeEnHuisnummer",
        "personen": [
            {
                "naam": {
                    "voornamen": "Ronald Franciscus Maria",
                    "geslachtsnaam": "Moes",
                    "voorletters": "R.F.M.",
                    "volledigeNaam": "Ronald Franciscus Maria Moes",
                    "aanduidingNaamgebruik": {
                        "code": "E",
                        "omschrijving": "eigen geslachtsnaam",
                    },
                }
            }
        ],
    }

    RESPONSE_BSN = {
        **RESPONSE_POSTCODE_HUISNUMMER,
        "type": "RaadpleegMetBurgerservicenummer",
    }

    @pytest.fixture
    def audit_log_handler(self, settings):
        """Set settings needed for audit log handler and temporary add the handler"""
        settings.AZURE_DATA_COLLECTION_ENDPOINT = "mock-endpoint"
        settings.AZURE_DATA_COLLECTION_RULE_ID = "mock-rule-id"
        settings.AZURE_DATA_COLLECTION_STREAM_NAME = "mock-stream-name"
        settings.MANAGED_IDENTITY_CLIENT_ID = "mock-client-id"

        handler = BRPAuditLogHandler()
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(CustomJsonFormatter("%(asctime)s $(levelname)s %(name)s %(message)s"))
        audit_log.addHandler(handler)

        yield

        # Remove the handler after the tests
        audit_log.removeHandler(handler)

    @patch("brp_amsterdam_api.bevragingen.loghandler.LogsIngestionClient.upload")
    def test_audit_log_handler(self, mock_log_upload, caplog, audit_log_handler):
        log_message = "Audit log message"
        audit_log.info(log_message)
        # Assert the upload function is called
        mock_log_upload.assert_called_with(
            rule_id="mock-rule-id", stream_name="mock-stream-name", logs=ANY
        )

        assert log_message in caplog.messages

    @patch("brp_amsterdam_api.bevragingen.loghandler.LogsIngestionClient.upload")
    def test_audit_log_handler_exception(self, mock_log_upload, audit_log_handler):
        mock_log_upload.side_effect = HttpResponseError("Failed to upload log")

        log_message = "Log message"
        with pytest.raises(AuditLogResponseError):
            audit_log.info(log_message)

    @patch("brp_amsterdam_api.bevragingen.loghandler.LogsIngestionClient.upload")
    def test_view_does_not_return_result_if_logging_fails(
        self, mock_log_upload, api_client, requests_mock, common_headers, audit_log_handler
    ):
        """Prove that no data is returned if our logging returns an error"""
        mock_log_upload.side_effect = HttpResponseError("Failed to upload log")

        requests_mock.post(
            "/lap/api/brp/personen",
            json=self.RESPONSE_BSN,
            headers={"content-type": "application/json"},
        )

        url = reverse("brp-personen")
        token = build_jwt_token(
            [
                "benk-brp-personen-api",
                "benk-brp-zoekvraag-bsn",
                "benk-brp-gegevensset-9",
            ]
        )
        with pytest.raises(AuditLogResponseError):
            response = api_client.post(
                f"{url}",
                {
                    "type": "RaadpleegMetBurgerservicenummer",
                    "burgerservicenummer": [""],
                    # No fields, is auto filled with all options of gegevensset-1.
                },
                headers={
                    "Authorization": f"Bearer {token}",
                    **common_headers,
                },
            )
            assert response.status_code == 500
