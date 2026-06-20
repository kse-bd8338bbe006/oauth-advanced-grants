# oauth-advanced-grants

Runnable Python demos for **API Security course - Lecture 7: Token Lifecycle and
Advanced OAuth Grants**. Each script talks to the course lab's Keycloak and shows
one RFC end to end. The scripts double as the fact-check for the lecture slides:
every claim on the deck is reproduced here against the live lab.

| Script | RFC | Shows |
|--------|-----|-------|
| `introspection_demo.py` | 7662 | introspect a valid and a garbage token; `active` is the only required field |
| `revocation_demo.py` | 7009 | client-ownership rule, refresh revocation kills the session, the local-validation propagation gap |
| `token_exchange_demo.py` | 8693 | internal-to-internal exchange; what Keycloak V2 does and does **not** do (no `act` delegation) |
| `dynamic_registration_demo.py` | 7591 / 7592 | protected registration, initial access token, manage + delete the client |
| `native_app_pkce_demo.py` | 8252 | Authorization Code + PKCE over a loopback redirect (no client secret) |
| `device_flow_demo.py` | 8628 | device + user codes, polling, `slow_down`, tokens |

## Lab facts (verified against Keycloak 26.3.3, realm `api-security`)

- `introspection_endpoint`, `revocation_endpoint`, `device_authorization_endpoint`,
  `registration_endpoint` are all published in the realm's
  `.well-known/openid-configuration`.
- `grant_types_supported` includes `urn:ietf:params:oauth:grant-type:token-exchange`
  and `urn:ietf:params:oauth:grant-type:device_code`; `code_challenge_methods_supported`
  includes `S256`.
- Standard Token Exchange is GA since Keycloak 26.2 and is **internal-to-internal,
  same-subject**; it does not emit the RFC 8693 `act` delegation claim and does not
  do cross-user impersonation (those were only in the deprecated V1).

## Prerequisites

- The lab cluster running, with Keycloak reachable at
  `https://keycloak.192.168.50.10.nip.io` and the Lecture 6 realm config in place
  (the `documents-api` confidential client must exist).
- Python 3.9+ and `pip install -r requirements.txt`.

## Setup (once)

```bash
pip install -r requirements.txt
python setup_lab.py     # idempotent: enables token exchange, adds the device + native clients
```

`setup_lab.py` uses the Keycloak admin API (`admin/admin`) to add only what the
demos need on top of the Lecture 6 realm:

- enables Standard Token Exchange on `documents-api`
- adds an audience mapper so `spa-token-demo` tokens list `documents-api` in `aud`
  (the requester must be in the subject token's audience to exchange it)
- creates `device-cli` (public, device grant) and `native-app-demo` (public, code
  + PKCE, loopback redirect)

## Run

```bash
python introspection_demo.py
python revocation_demo.py
python token_exchange_demo.py
python dynamic_registration_demo.py
python device_flow_demo.py                 # prints a code, approve in a browser
python device_flow_demo.py --auto-approve  # headless approval for testing
python native_app_pkce_demo.py             # opens your browser (interactive)
```

## Configuration

Defaults target the lab. Override with environment variables, e.g.:

```bash
export KC_BASE=https://keycloak.example.com
export REALM=api-security
export OAUTH_CA_BUNDLE=/path/to/ca.pem    # verify TLS instead of skipping
```

See `config.py` for all settings. The lab uses a self-signed internal CA, so TLS
verification is skipped unless `OAUTH_CA_BUNDLE` is set.

## Security notes

- These demos use the password grant for convenience to get a user token. Do not
  use the password grant in production - it is shown here only because the lab has
  fixed demo users.
- Introspection and revocation endpoints are client-authenticated. Treat the
  dynamic registration endpoint as attacker-reachable: require an initial access
  token, restrict redirect URIs, and watch for SSRF via metadata URLs.
