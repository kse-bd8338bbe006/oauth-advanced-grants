"""One-time lab setup for the Lecture 7 demos (idempotent).

Uses the Keycloak Admin API to add what these demos need on top of the
existing api-security realm:

  - documents-api: enable Standard Token Exchange (V2)
  - spa-token-demo: add an audience mapper for documents-api, so a token issued
    to the SPA lists documents-api in `aud` (the requester must be in the
    subject token's audience to exchange it)
  - device-cli: public client with the OAuth 2.0 Device Authorization Grant
  - native-app-demo: public client, Authorization Code + PKCE, loopback redirect
    (RFC 8252 native/desktop pattern)

Run once:  python setup_lab.py
"""
import config as c


def get_client(s, at, client_id):
    r = s.get(f"{c.ADMIN_BASE}/clients", params={"clientId": client_id},
              headers={"Authorization": f"Bearer {at}"})
    r.raise_for_status()
    arr = r.json()
    return arr[0] if arr else None


def ensure_token_exchange(s, at):
    cl = get_client(s, at, c.RESOURCE_CLIENT)
    if not cl:
        print(f"  ! {c.RESOURCE_CLIENT} not found - run the Lecture 6 setup first")
        return
    attrs = cl.get("attributes") or {}
    if attrs.get("standard.token.exchange.enabled") == "true":
        print(f"  = {c.RESOURCE_CLIENT}: token exchange already enabled")
        return
    attrs["standard.token.exchange.enabled"] = "true"
    cl["attributes"] = attrs
    r = s.put(f"{c.ADMIN_BASE}/clients/{cl['id']}", json=cl,
              headers={"Authorization": f"Bearer {at}"})
    r.raise_for_status()
    print(f"  + {c.RESOURCE_CLIENT}: enabled standard token exchange")


def ensure_audience_mapper(s, at):
    cl = get_client(s, at, c.PUBLIC_CLIENT)
    if not cl:
        print(f"  ! {c.PUBLIC_CLIENT} not found")
        return
    hdr = {"Authorization": f"Bearer {at}"}
    mappers = s.get(f"{c.ADMIN_BASE}/clients/{cl['id']}/protocol-mappers/models",
                    headers=hdr).json()
    if any(m["name"] == "documents-api-audience" for m in mappers):
        print(f"  = {c.PUBLIC_CLIENT}: audience mapper already present")
        return
    r = s.post(f"{c.ADMIN_BASE}/clients/{cl['id']}/protocol-mappers/models", headers=hdr, json={
        "name": "documents-api-audience", "protocol": "openid-connect",
        "protocolMapper": "oidc-audience-mapper",
        "config": {"included.client.audience": c.RESOURCE_CLIENT,
                   "access.token.claim": "true", "id.token.claim": "false"},
    })
    r.raise_for_status()
    print(f"  + {c.PUBLIC_CLIENT}: added audience mapper for {c.RESOURCE_CLIENT}")


def ensure_public_client(s, at, client_id, name, attributes=None,
                         standard_flow=False, device_flow=False, redirect_uris=None):
    cl = get_client(s, at, client_id)
    hdr = {"Authorization": f"Bearer {at}"}
    body = {
        "clientId": client_id, "name": name, "enabled": True,
        "publicClient": True, "standardFlowEnabled": standard_flow,
        "directAccessGrantsEnabled": False, "serviceAccountsEnabled": False,
        "redirectUris": redirect_uris or [],
        "attributes": attributes or {},
    }
    if device_flow:
        body["attributes"]["oauth2.device.authorization.grant.enabled"] = "true"
    if cl:
        body["id"] = cl["id"]
        r = s.put(f"{c.ADMIN_BASE}/clients/{cl['id']}", json=body, headers=hdr)
        r.raise_for_status()
        print(f"  = {client_id}: updated")
    else:
        r = s.post(f"{c.ADMIN_BASE}/clients", json=body, headers=hdr)
        r.raise_for_status()
        print(f"  + {client_id}: created")


def main():
    c.require_lab()
    s = c.session()
    at = c.admin_token(s)
    c.banner("Lecture 7 lab setup")
    ensure_token_exchange(s, at)
    ensure_audience_mapper(s, at)
    ensure_public_client(s, at, c.DEVICE_CLIENT, "Device/CLI demo (Lecture 7)",
                         device_flow=True)
    ensure_public_client(s, at, c.NATIVE_CLIENT, "Native app demo (Lecture 7)",
                         standard_flow=True,
                         redirect_uris=["http://127.0.0.1:*/callback",
                                        "http://localhost:*/callback"])
    print("\nDone. You can now run the demo scripts.")


if __name__ == "__main__":
    main()
