"""RFC 7009 - Token Revocation, and the propagation problem.

Two things this demo proves against the lab:

  1. Revocation is done by the client the token was ISSUED TO. Trying to revoke
     another client's token fails with 400 "Unmatching clients".
  2. Revoking the refresh token kills the session: the refresh token and the
     access token both introspect as inactive, and refresh stops working.
     BUT the access token JWT is still unexpired, so a resource server doing
     ONLY local validation would keep accepting it until `exp`. That gap is why
     you pair revocation with short token lifetimes (or introspection).

Run:  python revocation_demo.py
"""
import time

import config as c


def introspect(s, token):
    return s.post(c.INTROSPECT_URL, auth=(c.RESOURCE_CLIENT, c.RESOURCE_SECRET),
                  data={"token": token}).json()


def main():
    c.require_lab()
    s = c.session()

    c.banner("1. Get an access + refresh token (public client)")
    tok = c.user_token(s, scope="openid")
    access, refresh = tok["access_token"], tok["refresh_token"]
    exp = c.decode_jwt(access)["exp"]
    print(f"access_token lifetime: ~{exp - int(time.time())}s")

    c.banner("2. Wrong client tries to revoke -> 400 (RFC 7009 ownership rule)")
    r = s.post(c.REVOKE_URL, auth=(c.RESOURCE_CLIENT, c.RESOURCE_SECRET),
               data={"token": refresh, "token_type_hint": "refresh_token"})
    print(f"HTTP {r.status_code}: {r.text}")

    c.banner("3. The owning (public) client revokes the refresh token")
    r = s.post(c.REVOKE_URL, data={"client_id": c.PUBLIC_CLIENT,
               "token": refresh, "token_type_hint": "refresh_token"})
    print(f"HTTP {r.status_code} (RFC 7009: 200 even if already invalid)")

    c.banner("4. After revoke - the issuer's view")
    print("refresh introspects active:", introspect(s, refresh)["active"])
    print("access  introspects active:", introspect(s, access)["active"])
    rr = s.post(c.TOKEN_URL, data={"grant_type": "refresh_token",
                "client_id": c.PUBLIC_CLIENT, "refresh_token": refresh}).json()
    print("re-use refresh token:", rr.get("error"), "-", rr.get("error_description"))

    c.banner("5. The propagation gap")
    still = exp - int(time.time())
    print(f"The access token JWT is STILL unexpired for ~{still}s.")
    print("A resource server doing only local signature+exp validation would")
    print("keep accepting this revoked token until it expires.")
    print("\nFixes: short access-token TTL + refresh revocation (default), or")
    print("introspection at the RS, or OIDC back-channel logout.")


if __name__ == "__main__":
    main()
