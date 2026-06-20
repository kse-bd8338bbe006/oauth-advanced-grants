"""Shared configuration and helpers for the Lecture 7 OAuth demos.

Everything points at the API Security course lab by default. Override any value
with an environment variable (see below). The lab uses a self-signed internal
CA, so TLS verification is off unless you set OAUTH_CA_BUNDLE.
"""
import base64
import json
import os
import sys

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- lab endpoints -----------------------------------------------------------
KC_BASE = os.environ.get("KC_BASE", "https://keycloak.192.168.50.10.nip.io")
REALM = os.environ.get("REALM", "api-security")

OIDC = f"{KC_BASE}/realms/{REALM}/protocol/openid-connect"
TOKEN_URL = f"{OIDC}/token"
INTROSPECT_URL = f"{OIDC}/token/introspect"
REVOKE_URL = f"{OIDC}/revoke"
DEVICE_URL = f"{OIDC}/auth/device"
AUTH_URL = f"{OIDC}/auth"
REGISTRATION_URL = f"{KC_BASE}/realms/{REALM}/clients-registrations/openid-connect"
ADMIN_BASE = f"{KC_BASE}/admin/realms/{REALM}"

# --- clients and users (lab defaults) ---------------------------------------
PUBLIC_CLIENT = os.environ.get("PUBLIC_CLIENT", "spa-token-demo")
RESOURCE_CLIENT = os.environ.get("RESOURCE_CLIENT", "documents-api")
RESOURCE_SECRET = os.environ.get("RESOURCE_SECRET", "documents-api-secret-lab-2026")
DEVICE_CLIENT = os.environ.get("DEVICE_CLIENT", "device-cli")
NATIVE_CLIENT = os.environ.get("NATIVE_CLIENT", "native-app-demo")

DEMO_USER = os.environ.get("DEMO_USER", "alice")
DEMO_PASS = os.environ.get("DEMO_PASS", "alice")

ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin")

# TLS: lab is self-signed. Point OAUTH_CA_BUNDLE at a CA file to verify properly.
VERIFY = os.environ.get("OAUTH_CA_BUNDLE", False)


def session():
    s = requests.Session()
    s.verify = VERIFY
    return s


def user_token(s, client_id=PUBLIC_CLIENT, username=DEMO_USER, password=DEMO_PASS,
               scope="openid"):
    """Direct access grant (password) - lab convenience, not for production."""
    r = s.post(TOKEN_URL, data={
        "grant_type": "password", "client_id": client_id,
        "username": username, "password": password, "scope": scope,
    })
    r.raise_for_status()
    return r.json()


def admin_token(s):
    """Master-realm admin token for setup / IAT minting."""
    r = s.post(f"{KC_BASE}/realms/master/protocol/openid-connect/token", data={
        "grant_type": "password", "client_id": "admin-cli",
        "username": ADMIN_USER, "password": ADMIN_PASS,
    })
    r.raise_for_status()
    return r.json()["access_token"]


def decode_jwt(token):
    """Decode a JWT payload WITHOUT verifying. Inspection only - never trust this
    for a security decision; that is what introspection / signature checks are for.
    """
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def jprint(obj):
    print(json.dumps(obj, indent=2, sort_keys=True))


def banner(text):
    line = "=" * len(text)
    print(f"\n{line}\n{text}\n{line}")


def require_lab():
    """Fail fast with a clear message if the lab is unreachable."""
    try:
        r = session().get(f"{KC_BASE}/realms/{REALM}/.well-known/openid-configuration",
                           timeout=8)
        r.raise_for_status()
    except Exception as e:  # noqa: BLE001
        print(f"Cannot reach Keycloak at {KC_BASE} realm '{REALM}': {e}")
        print("Is the lab cluster up? See the lab setup guide.")
        sys.exit(1)
