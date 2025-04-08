from django.urls import path

from . import views

urlpatterns = [
    path("brp/personen", views.BrpPersonenView.as_view(), name="brp-personen"),
    path("brp/bewoningen", views.BrpBewoningenView.as_view(), name="brp-bewoningen"),
    path(
        "brp/verblijfplaatshistorie",
        views.BrpVerblijfplaatshistorieView.as_view(),
        name="brp-verblijfplaatshistorie",
    ),
]
