# Haal Centraal API

This is a proxy service to connect to the Haal Centraal API.
It filters requests and enforces token-based authorization.

# Reason

Haal Centraal offers national services for accessing government data.
These services are designed to support broad access, and don't offer much refined authorization policies.
Such feature has to be implemented by each municipality that implements the API.

This service does this based on policy files (tbd, but likely in "Amsterdam Schema").

# Installation

Requirements:

* Python >= 3.12
* Recommended: Docker/Docker Compose (or pyenv for local installs)

## Using Docker Compose

Run docker compose:
```shell
docker compose up
```

Navigate to `localhost:8095`.

The mock API uses the following data file: https://github.com/BRP-API/Haal-Centraal-BRP-bevragen/blob/master/src/config/BrpService/test-data.json

Example request (directly to the Haal Centraal Mock API):

    curl -X POST http://localhost:5010/haalcentraal/api/brp/personen -H 'Content-Type: application/json' -d '{"type": "ZoekMetPostcodeEnHuisnummer", "postcode": "1074VE", "huisnummer": 1, "fields": ["naam"]}'

And the same can be repeated on the Django instance if you pass a token:

    curl -X POST http://localhost:8000/api/brp/personen -H 'Content-Type: application/json' -H "Authorization: Bearer $(./get-token.py BRP/RO BRP/zoek-postcode)" -d '{"type": "ZoekMetPostcodeEnHuisnummer", "postcode": "1074VE", "huisnummer": 1, "fields": ["naam"]}'

The *type* and *fields* are required for all request types.
All possible parameters are documented in the [Haal Centraal documentation](https://brp-api.github.io/Haal-Centraal-BRP-bevragen/).

## Using Local Python

Create a virtualenv:

```shell
python3 -m venv venv
source venv/bin/activate
```

Install all packages in it:
```shell
pip install -U wheel pip
cd src/
make install  # installs src/requirements_dev.txt
```

Start the Django application:
```shell
export PUB_JWKS="$(cat jwks_test.json)"
export HAAL_CENTRAAL_BRP_URL="http://localhost:5010/haalcentraal/api/brp/personen"
export DJANGO_DEBUG=true

./manage.py runserver localhost:8000
```

## Environment Settings

The following environment variables are useful for configuring a local development environment:

* `DJANGO_DEBUG` to enable debugging (true/false).
* `LOG_LEVEL` log level for application code.
* `AUDIT_LOG_LEVEL` log level for audit messages (default is `INFO`).

Connections:

* `HAAL_CENTRAAL_BRP_PERSONEN_URL` endpoint for the Haal Centraal BRP Personen API.
* `HAAL_CENTRAAL_BRP_BEWONINGEN_URL` endpoint for the BRP occupancy URL.
* `HAAL_CENTRAAL_BRP_VERBLIJFSPLAATS_HISTORIE_URL` endpoint for the address history URL.
* `HAAL_CENTRAAL_REISDOCUMENTEN_URL` endpoint for the travel documents URL.
* `HAAL_CENTRAAL_API_KEY` the API key for Haal Centraal
* `HAAL_CENTRAAL_CERT_FILE` the mTLS certificate for Haal Centraal.
* `HAAL_CENTRAAL_KEY_FILE` the mTLS key file for Haal Centraal.

Deployment:

* `ALLOWED_HOSTS` will limit which domain names can connect.
* `AZURE_APPI_CONNECTION_STRING` Azure Insights configuration.
* `AZURE_APPI_AUDIT_CONNECTION_STRING` Same, for a special audit logging.
* `CLOUD_ENV=azure` will enable Azure-specific telemetry.
* `SECRET_KEY` is used for various encryption code.
* `STATIC_URL` defines the base URL for static files (e.g. to point to a CDN).
* `PUB_JWKS` or `OAUTH_JWKS_URL` point to a public JWT key.

# Developer Notes

Run `make` in the `src` folder to have an help-overview of all common developer tasks.

## Package Management

The packages are managed with *pip-compile*.

To add a package, update the `requirements.in` file and run `make requirements`.
This will update the "lockfile" aka `requirements.txt` that's used for pip installs.

To upgrade all packages, run `make upgrade`, followed by `make install` and `make test`.
Or at once if you feel lucky: `make upgrade install test`.

## Environment Settings

Consider using *direnv* for automatic activation of environment variables.
It automatically sources an ``.envrc`` file when you enter the directory.
This file should contain all lines in the `export VAR=value` format.

In a similar way, *pyenv* helps to install the exact Python version,
and will automatically activate the virtualenv when a `.python-version` file is found:

```shell
pyenv install 3.12.4
pyenv virtualenv 3.12.4 haal-centraal-proxy
echo haal-centraal-proxy > .python-version
```
