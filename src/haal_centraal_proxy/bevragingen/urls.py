from django.urls import path

from . import views

urlpatterns = [
    path("v1/personen", views.BrpPersonenView.as_view(), name="brp-personen"),
    path("v1/bewoningen", views.BrpBewoningenView.as_view(), name="brp-bewoningen"),
    path(
        "v1/verblijfplaatshistorie",
        views.BrpVerblijfplaatshistorieView.as_view(),
        name="brp-verblijfplaatshistorie",
    ),
]
