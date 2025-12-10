import requests
from rest_framework import status
from rest_framework.exceptions import APIException
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response

from .base import BaseBrpClient


class BrpVAdhocServiceClient(BaseBrpClient):
    """
    BRP V Adhoc Service Client for connection to the ad-hoc BRP service to request partner history
    since this (currently) isn't part of the RvIG BRP APIs.
    """

    def call(self, hc_request: dict | None = None) -> requests.Response | APIException:
        # Mock response untill we have a connection
        response = Response(data={"status": "ok"}, status=status.HTTP_200_OK)
        response.accepted_renderer = JSONRenderer()
        response.accepted_media_type = "application/json"
        response.renderer_context = {}
        response.render()
        return response
