import os

import requests
from authlib.integrations.django_client import OAuth
from joserfc import jwt
from joserfc.errors import InvalidKeyIdError
from joserfc.jwk import KeySet
from joserfc.jws import JWSRegistry
from joserfc.jwt import JWTClaimsRegistry


oauth = OAuth()

PUBLIC_URL = os.environ["KEYCLOAK_PUBLIC_URL"]
INTERNAL_URL = os.environ["KEYCLOAK_INTERNAL_URL"]
REALM = os.environ["KEYCLOAK_REALM"]
CLIENT_ID = os.environ["KEYCLOAK_CLIENT_ID"]
CLIENT_SECRET = os.environ["KEYCLOAK_CLIENT_SECRET"]
ISSUER = f"{PUBLIC_URL.rstrip('/')}/realms/{REALM}"
SIGNING_ALGORITHMS = tuple(
    algorithm.strip()
    for algorithm in os.environ.get("KEYCLOAK_SIGNING_ALGORITHMS", "RS256").split(",")
    if algorithm.strip()
)


oauth.register(
    name="keycloak",

    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,

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


def verified_access_token_claims(token_response):
    """Verify and return claims from the Keycloak access token."""
    encoded_token = token_response.get("access_token")
    if not encoded_token:
        return {}

    registry = JWSRegistry(
        algorithms=SIGNING_ALGORITHMS,
        strict_check_header=False,
    )
    key_set = KeySet.import_key_set(oauth.keycloak.fetch_jwk_set())
    try:
        decoded = jwt.decode(encoded_token, key=key_set, registry=registry)
    except InvalidKeyIdError:
        key_set = KeySet.import_key_set(oauth.keycloak.fetch_jwk_set(force=True))
        decoded = jwt.decode(encoded_token, key=key_set, registry=registry)

    claims = dict(decoded.claims)
    JWTClaimsRegistry(
        leeway=120,
        iss={"essential": True, "value": ISSUER},
        sub={"essential": True},
        exp={"essential": True},
    ).validate(claims)

    audience = claims.get("aud", [])
    if isinstance(audience, str):
        audience = [audience]
    if claims.get("azp") != CLIENT_ID and CLIENT_ID not in audience:
        raise ValueError("Access token was not issued to this client")

    return claims


def refresh_keycloak_token(refresh_token):
    """Exchange a server-side refresh token for fresh Keycloak claims."""
    response = requests.post(
        f"{INTERNAL_URL.rstrip('/')}/realms/{REALM}/protocol/openid-connect/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        },
        auth=(CLIENT_ID, CLIENT_SECRET),
        timeout=10,
    )
    response.raise_for_status()
    return response.json()
