"""RFC 7591 - Dynamic Client Registration (+ RFC 7592 management).

Shows, against the lab:
  - Anonymous registration is rejected (the realm requires authorization).
  - An admin mints an Initial Access Token (IAT); registration with the IAT
    succeeds and returns client_id, client_secret, a registration_access_token
    and registration_client_uri.
  - The registration_access_token manages that one client (RFC 7592): here we
    read it back, then delete it to clean up.

Run:  python dynamic_registration_demo.py
"""
import config as c

METADATA = {
    "client_name": "L7 DCR Demo",
    "redirect_uris": ["https://demo.example/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "token_endpoint_auth_method": "client_secret_basic",
}


def create_initial_access_token(s):
    at = c.admin_token(s)
    r = s.post(f"{c.ADMIN_BASE}/clients-initial-access",
               headers={"Authorization": f"Bearer {at}"},
               json={"count": 1, "expiration": 300})
    r.raise_for_status()
    return r.json()["token"]


def main():
    c.require_lab()
    s = c.session()

    c.banner("1. Anonymous registration is rejected (protected registration)")
    r = s.post(c.REGISTRATION_URL, json=METADATA)
    print(f"HTTP {r.status_code} (open registration is OFF - good)")

    c.banner("2. Admin mints an Initial Access Token (IAT)")
    iat = create_initial_access_token(s)
    print(f"IAT: {iat[:24]}...  (count-limited, short-lived)")

    c.banner("3. Register the client with the IAT")
    r = s.post(c.REGISTRATION_URL, headers={"Authorization": f"Bearer {iat}"},
               json=METADATA)
    print(f"HTTP {r.status_code}")
    reg = r.json()
    print("client_id:", reg.get("client_id"))
    print("client_secret issued:", bool(reg.get("client_secret")))
    print("registration_access_token issued:", bool(reg.get("registration_access_token")))
    print("registration_client_uri:", reg.get("registration_client_uri"))

    rat = reg["registration_access_token"]
    rcu = reg["registration_client_uri"]

    c.banner("4. Manage the client with its registration token (RFC 7592)")
    got = s.get(rcu, headers={"Authorization": f"Bearer {rat}"})
    print("GET self:", got.status_code, "-> client_name:", got.json().get("client_name"))

    c.banner("5. Clean up - delete the registered client (RFC 7592)")
    d = s.delete(rcu, headers={"Authorization": f"Bearer {rat}"})
    print("DELETE self:", d.status_code)

    c.banner("Security note")
    print("The registration endpoint is attacker-reachable. Require an IAT,\n"
          "restrict redirect_uris, watch for SSRF via metadata URLs\n"
          "(jwks_uri/logo_uri), and rate-limit. Keycloak adds Client\n"
          "Registration Policies to bound what a new client may request.")


if __name__ == "__main__":
    main()
