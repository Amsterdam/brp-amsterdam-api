from django.conf import settings
from django.conf.urls.static import static
from django.urls import include, path

import haal_centraal_proxy.bevragingen.urls

from . import views

handler400 = views.bad_request
handler404 = views.not_found
handler500 = views.server_error

urlpatterns = [
    path("bevragingen/", include(haal_centraal_proxy.bevragingen.urls)),
    path("", views.RootView.as_view()),
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

if "debug_toolbar" in settings.INSTALLED_APPS:
    import debug_toolbar

    urlpatterns.append(path("__debug__/", include(debug_toolbar.urls)))
