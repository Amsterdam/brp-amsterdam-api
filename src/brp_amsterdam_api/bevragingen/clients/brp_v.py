import requests
from django.conf import settings
from rest_framework import status
from rest_framework.exceptions import APIException
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from zeep import Client, Transport

from .base import BaseBrpClient


class BrpVAdhocServiceClient(BaseBrpClient):
    """
    BRP V Adhoc Service Client for connection to the ad-hoc BRP service to request partner history
    since this (currently) isn't part of the RvIG BRP APIs.
    """

    def __init__(
        self,
        endpoint_url,
        *,
        user: str | None = None,
        password: str | None = None,
        cert_file=None,
        key_file=None,
    ):
        super().__init__(endpoint_url, cert_file=cert_file, key_file=key_file)

        # Add basic auth to the session
        self._session.auth = (user, password)

        # Import the WSDL locally to bypass http import in the online file
        wsdl = f"{settings.SRC_DIR}/brp_amsterdam_api/bevragingen/clients/lrd_plus.wsdl"
        transport = Transport(session=self._session)
        self.client = Client(wsdl=wsdl, transport=transport)
        self.factory = self.client.type_factory("ns0")

    def call(self, hc_request: dict | None = None) -> requests.Response | APIException:
        # Mock response untill we have a connection
        response = Response(data={"status": "ok"}, status=status.HTTP_200_OK)
        response.accepted_renderer = JSONRenderer()
        response.accepted_media_type = "application/json"
        response.renderer_context = {}
        response.render()
        return response
