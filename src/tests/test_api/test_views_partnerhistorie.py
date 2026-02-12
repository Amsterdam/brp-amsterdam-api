from django.urls import reverse

from tests.utils import build_jwt_token


class TestBrpPartnerhistorieView:
    """Prove that the BRP view works as advertised.

    This includes tests that are specific for the BRP (not generic tests).
    """

    def test_partnerhistorie_view(self, api_client, requests_mock, common_headers):
        """Prove that search is possible"""
        with open("tests/data/example.xml").read() as mock_response:

            requests_mock.post("/gba-v/online/lo3services/adhoc", text=mock_response)

            url = reverse("brp-partnerhistorie")
            token = build_jwt_token(
                [
                    "benk-brp-personen-api",
                    "benk-brp-partnerhistorie-api",
                ]
            )
            response = api_client.post(
                url,
                {"type": "RaadpleegMetBurgerservicenummer", "burgerservicenummer": "123456789"},
                headers={
                    "Authorization": f"Bearer {token}",
                    **common_headers,
                },
            )
            assert response.status_code == 200, response.data
            assert response.json() == {
                "partnerhistorie": [
                    {
                        "geslacht": "V",
                        "naam": {
                            "geslachtsnaam": "Ayaan Nasra Si'id Ahmed",
                            "inOnderzoek": "050000",
                        },
                        "soortVerbintenis": "H",
                    },
                ]
            }
