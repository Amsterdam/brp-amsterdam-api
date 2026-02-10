# BRP Amsterdam API - Integration Tests

These integration tests have been set up to make sure all connections to the external API's (RvIG) still
work when deploying changes to the application or underlying infrastucture.

# Installation

Requirements:

* Python >= 3.14
* Recommended: Docker/Docker Compose (or uv for local installs)

## BRP Amsterdam API

The easiest way to run these integration tests is by using Docker Compose. This will also start the BRP Amsterdam API
and the BRP Personen Mock.

To be able to run the tests you will need a valid token to be able to make the requests. The easiest way is to set up
direnv with an `.envrc` file or export a token from the command line:

```shell
export TOKEN="$(docker compose run web python get-token.py benk-brp-personen-api benk-brp-gegevensset-1 benk-brp-zoekvraag-bsn benk-brp-zoekvraag-geslachtsnaam-geboortedatum benk-brp-zoekvraag-naam-gemeente benk-brp-zoekvraag-adresseerbaar-object benk-brp-zoekvraag-nummeraanduiding benk-brp-zoekvraag-postcode-huisnummer benk-brp-zoekvraag-straatnaam-huisnummer benk-brp-bewoning-api benk-brp-verblijfplaatshistorie-api)"
```

After having a valid token in your environment you'll be able to start the tests using:

```shell
docker compose run tests
```

The BRP Personen Mock only has the `personen` endpoint available, so running the tests against the `bewoningen` and
`verblijfplaatshistorie` will result in a failed test. To see the test run succesfully you can run the tests for the
`personen` endpoint only:

```shell
docker compose run tests -e personen
```

## Using Local Python

Make sure you have the BRP Amsterdam API and BRP Personen Mock running

```shell
docker compose up -d -f ../docker-compose.yml
```

```shell
uv sync
```
