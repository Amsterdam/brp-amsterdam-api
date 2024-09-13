from haal_centraal_proxy.settings import *  # noqa: F403, F405

# The reason the settings are defined here, is to make them independent
# of the regular project sources. Otherwise, the project needs to have
# knowledge of the test framework.


OAUTH_URL = ""

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.dummy.DummyCache",
    }
}

CSRF_COOKIE_SECURE = False
SESSION_COOKIE_SECURE = False

# Load public/private test key pair.
# This was obtained in the authz project with: jwkgen -create -alg ES256
jwks_key = Path(__file__).parent.parent.joinpath("jwks_test.json").read_text()

DATAPUNT_AUTHZ = {
    "JWKS": jwks_key,
    "ALWAYS_OK": False,
    "MIN_INTERVAL_KEYSET_UPDATE": 30 * 60,  # 30 minutes
}

# Remove propagate=False so caplog can read those messages.
LOGGING = {
    **LOGGING,
    "loggers": {
        name: {
            **conf,
            "propagate": True,
        }
        for name, conf in LOGGING["handlers"].items()
    },
}

PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]

# Prevent tests to crash because of missing staticfiles manifests
WHITENOISE_MANIFEST_STRICT = False
STORAGES = {
    **STORAGES,
    "staticfiles": {
        "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage",
    },
}

# Use different default:
HAAL_CENTRAAL_BRP_URL = env.str(
    "HAAL_CENTRAAL_BRP_URL", "http://localhost:5010/haalcentraal/api/brp/personen"
)
