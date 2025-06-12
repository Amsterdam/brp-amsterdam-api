from django.urls import path
from django.views.generic import RedirectView

from . import views

urlpatterns = [
    path("", RedirectView.as_view(pattern_name="brp-index")),
    path("v1/", views.IndexView.as_view(), name="brp-index"),
    # API's
    path("v1/personen", views.BrpPersonenView.as_view(), name="brp-personen"),
    path("v1/bewoningen", views.BrpBewoningenView.as_view(), name="brp-bewoningen"),
    path(
        "v1/verblijfplaatshistorie",
        views.BrpVerblijfplaatshistorieView.as_view(),
        name="brp-verblijfplaatshistorie",
    ),
]

health_urls = [
    # Healthchecks
    path("personen", views.BrpPersonenHealthView.as_view(), name="brp-personen-health"),
    path("bewoningen", views.BrpBewoningenHealthView.as_view(), name="brp-bewoningen-health"),
    path(
        "verblijfplaatshistorie",
        views.BrpVerblijfplaatshistorieHealthView.as_view(),
        name="brp-verblijfplaatshistorie-health",
    ),
]
