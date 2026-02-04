# BRP Amsterdam API - Integration Tests

These integration tests have been set up to make sure all connections to the external API's (RvIG) still
work when deploying changes to the application or underlying infrastucture.

# Installation

Requirements:

* Python >= 3.14
* Recommended: Docker/Docker Compose (or uv for local installs)

## BRP Amsterdam API

Make sure you have a local development environment of the BRP Amsterdam API running. The easiest option is using
Docker Compose:
```shell
cd ..
docker compose up -d
```

And return to the integration_tests directory.

## Using Docker Compose

Run docker compose:
```shell
docker compose up
```

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
