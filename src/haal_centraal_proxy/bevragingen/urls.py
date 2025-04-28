from django.urls import path
from django.views.generic import RedirectView

from . import views

urlpatterns = [
    path("", RedirectView.as_view(pattern_name="brp-index")),
    path("v1/", views.IndexView.as_view(), name="brp-index"),
    path("v1/personen", views.BrpPersonenView.as_view(), name="brp-personen"),
    path("v1/bewoningen", views.BrpBewoningenView.as_view(), name="brp-bewoningen"),
    path(
        "v1/verblijfplaatshistorie",
        views.BrpVerblijfplaatshistorieView.as_view(),
        name="brp-verblijfplaatshistorie",
    ),
]
