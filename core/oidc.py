import os

from authlib.integrations.django_client import OAuth


oauth = OAuth()

PUBLIC_URL = os.environ["KEYCLOAK_PUBLIC_URL"]
INTERNAL_URL = os.environ["KEYCLOAK_INTERNAL_URL"]
REALM = os.environ["KEYCLOAK_REALM"]


oauth.register(
    name="keycloak",

    client_id=os.environ["KEYCLOAK_CLIENT_ID"],
    client_secret=os.environ["KEYCLOAK_CLIENT_SECRET"],

    authorize_url=(
        f"{PUBLIC_URL}/realms/{REALM}/"
        "protocol/openid-connect/auth"
    ),

    access_token_url=(
        f"{INTERNAL_URL}/realms/{REALM}/"
        "protocol/openid-connect/token"
    ),

    userinfo_endpoint=(
        f"{INTERNAL_URL}/realms/{REALM}/"
        "protocol/openid-connect/userinfo"
    ),

    jwks_uri=(
        f"{INTERNAL_URL}/realms/{REALM}/"
        "protocol/openid-connect/certs"
    ),

    client_kwargs={
        "scope": "openid profile email",
    },
)
