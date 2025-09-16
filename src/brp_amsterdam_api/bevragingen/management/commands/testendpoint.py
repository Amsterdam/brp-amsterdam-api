import logging
from http.client import HTTPConnection

from django.conf import settings
from django.core.management import BaseCommand, CommandError, CommandParser
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.urllib import URLLibInstrumentor
from opentelemetry.instrumentation.urllib3 import URLLib3Instrumentor

from brp_amsterdam_api.bevragingen.client import BrpClient
from brp_amsterdam_api.bevragingen.exceptions import RemoteAPIException

ENDPOINTS = {
    "personen": settings.BRP_PERSONEN_URL,
    "bewoningen": settings.BRP_BEWONINGEN_URL,
    "verblijf": settings.BRP_VERBLIJFPLAATSHISTORIE_URL,
}


class Command(BaseCommand):
    help = "Debugging tool for ops to test BRP endpoint connectivity"

    def add_arguments(self, parser: CommandParser):
        parser.add_argument("--endpoint", choices=sorted(ENDPOINTS.keys()), default="personen")

    def handle(self, *args, **options):
        # Increase logging
        urllib_logger = logging.getLogger("urllib3")
        urllib_logger.setLevel(logging.DEBUG)
        urllib_logger.addHandler(logging.StreamHandler(stream=self.stderr))
        urllib_logger.propagate = False
        HTTPConnection.debuglevel = 2

        RequestsInstrumentor().uninstrument()
        URLLibInstrumentor().uninstrument()
        URLLib3Instrumentor().uninstrument()

        endpoint_type = options["endpoint"]
        client = BrpClient(
            endpoint_url=ENDPOINTS[endpoint_type],
            oauth_endpoint_url=settings.BRP_OAUTH_TOKEN_URL,
            oauth_client_id=settings.BRP_OAUTH_CLIENT_ID,
            oauth_client_secret=settings.BRP_OAUTH_CLIENT_SECRET,
            oauth_scope=settings.BRP_OAUTH_SCOPE,
            cert_file=settings.BRP_MTLS_CERT_FILE,
            key_file=settings.BRP_MTLS_KEY_FILE,
        )

        self.stdout.write("Using settings:")
        for name in dir(settings):
            if name.startswith("BRP_"):
                self.stdout.write(f"  {name}={getattr(settings, name)}")

        self.stdout.write(f"Retrieving token from {client.oauth_endpoint_url}...")
        self.stdout.write(f"  client_id={settings.BRP_OAUTH_CLIENT_ID}")
        self.stdout.write(f"  client_secret={settings.BRP_OAUTH_CLIENT_SECRET}")
        self.stdout.write(f"  scope={settings.BRP_OAUTH_SCOPE}")
        client.fetch_token()

        try:
            hc_response = client.call({"type": "healthcheck"})
        except RemoteAPIException as e:
            # Remote server doesn't like this request, but we do have connection!
            if e.detail == "De foutieve parameter(s) zijn: type.":
                self.stdout.write(
                    self.style.SUCCESS("Got connection, and response from healthcheck probe!")
                )
                return
            self.stdout.write(str(e))
        except OSError as e:
            raise CommandError(str(e)) from e

        self.stdout.write(hc_response.content)
        self.stdout.write(self.style.SUCCESS("Test BRP endpoint connectivity"))
