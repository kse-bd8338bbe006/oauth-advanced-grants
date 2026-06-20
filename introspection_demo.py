"""RFC 7662 - Token Introspection.

Local validation answers "is this JWT well-formed and signed?". Introspection
asks the issuer the stronger question: "do you still consider this token active
right now?" - which reflects revocation and session state that a local check
cannot see.

The introspection endpoint is PROTECTED: the caller authenticates as a client.
Here the caller is the confidential `documents-api` (a resource server).

Run:  python introspection_demo.py
"""
import config as c


def introspect(s, token, token_type_hint="access_token"):
    r = s.post(c.INTROSPECT_URL,
               auth=(c.RESOURCE_CLIENT, c.RESOURCE_SECRET),
               data={"token": token, "token_type_hint": token_type_hint})
    r.raise_for_status()
    return r.json()


def main():
    c.require_lab()
    s = c.session()

    c.banner("1. Get a user access token (public client, for the demo)")
    tok = c.user_token(s, scope="openid profile")
    access = tok["access_token"]
    print(f"access_token: {access[:24]}...")

    c.banner("2. Introspect a VALID token")
    active = introspect(s, access)
    c.jprint({k: active.get(k) for k in
              ["active", "username", "scope", "client_id", "token_type", "exp"]})
    assert active["active"] is True, "expected active token"
    print("\n-> `active` is the only REQUIRED field in the response (RFC 7662).")

    c.banner("3. Introspect a GARBAGE token")
    bad = introspect(s, "not-a-real-token")
    c.jprint(bad)
    assert bad["active"] is False
    print("\n-> An inactive/unknown token returns just {\"active\": false} - "
          "never any claims.")

    c.banner("Takeaway")
    print("Introspection costs one call to the issuer but reflects the issuer's\n"
          "current view (revocation, logout). Use it where freshness matters;\n"
          "validate JWTs locally where throughput matters. Cache briefly to blend.")


if __name__ == "__main__":
    main()
