from fnmatch import fnmatch

from django.urls import get_resolver
from rest_framework.response import Response
from rest_framework.views import APIView


class IndexView(APIView):
    """Having some response on the /bevragingen/v1/ path fixes the healthcheck."""

    def get(self, request):
        return Response(
            {
                "status": "online",
                "paths": self._list_urls(),
            }
        )

    def _list_urls(self):
        patterns = get_resolver().url_patterns
        return _extract_patterns(patterns, prefix="/", match="/bevragingen/v1/?*")


def _extract_patterns(patterns, prefix, match):
    urls = []
    for pattern in patterns:
        url = f"{prefix}{pattern.pattern}"
        if hasattr(pattern, "url_patterns") and match.startswith(url):
            urls.extend(_extract_patterns(pattern.url_patterns, url, match))
        elif fnmatch(url, match):
            urls.append(url)
    return urls
