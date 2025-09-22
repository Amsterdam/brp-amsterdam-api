import logging

from azure.core.exceptions import HttpResponseError
from azure.identity import DefaultAzureCredential
from azure.monitor.ingestion import LogsIngestionClient
from django.conf import settings

logger = logging.getLogger(__name__)


class AuditLogResponseError(Exception):
    pass


class BRPAuditLogHandler(logging.Handler):

    def __init__(self):
        super().__init__()
        self.endpoint = settings.AZURE_DATA_COLLECTION_ENDPOINT
        self.rule_id = settings.AZURE_DATA_COLLECTION_RULE_ID
        self.stream_name = settings.AZURE_DATA_COLLECTION_STREAM_NAME

        self._credential = DefaultAzureCredential()
        self._client = LogsIngestionClient(
            endpoint=self.endpoint, credential=self._credential, logging_enable=True
        )

    def emit(self, record) -> None:
        # Data collection endpoint expects a list of records
        if not isinstance(record, list):
            record = [record]

        try:
            self._client.upload(
                rule_id=self.rule_id,
                stream_name=self.stream_name,
                logs=[self.format(r) for r in record],
            )
        except HttpResponseError as e:
            logger.error(e)
            raise AuditLogResponseError("Failed to emit audit log") from e
