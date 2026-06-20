"""RFC 8693 - Token Exchange (Keycloak Standard Token Exchange, V2).

Scenario: the user logs into the SPA (spa-token-demo). The SPA's token lists
`documents-api` in its audience. The `documents-api` service exchanges that
token for one issued to ITSELF for the same user - the internal-to-internal
pattern used to carry a user's identity across a call chain.

What Keycloak's Standard Token Exchange (GA since 26.2, lab runs 26.3.3) does
and does NOT do - verified against the lab:

  - It issues a new token for the SAME subject (sub stays the user; azp becomes
    the requesting client). The requester must be in the subject token's `aud`.
  - The `scope` parameter ADDS optional client scopes (RFC 8693 calls this
    flexible); strict downscoping needs the `downscope` policy executor.
  - It does NOT implement RFC 8693 delegation: passing `actor_token` does not
    produce an `act` claim. Cross-user impersonation is also not in V2 (it was
    only in the deprecated V1). The `act`/impersonation slides describe the
    STANDARD; Keycloak V2 implements the internal-to-internal subset.

Run:  python token_exchange_demo.py
"""
import config as c

TE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"


def main():
    c.require_lab()
    s = c.session()

    c.banner("1. User logs into the SPA; token must name documents-api in aud")
    subject = c.user_token(s, scope="openid profile email")["access_token"]
    claims = c.decode_jwt(subject)
    print("subject token: sub =", claims.get("preferred_username"),
          "| azp =", claims.get("azp"), "| aud =", claims.get("aud"))
    if c.RESOURCE_CLIENT not in (claims.get("aud") or []):
        print(f"\n! {c.RESOURCE_CLIENT} is not in aud - run setup_lab.py first "
              "(it adds the audience mapper).")
        return

    c.banner("2. documents-api exchanges the user's token for its own")
    r = s.post(c.TOKEN_URL, auth=(c.RESOURCE_CLIENT, c.RESOURCE_SECRET), data={
        "grant_type": TE_GRANT,
        "subject_token": subject, "subject_token_type": ACCESS_TOKEN_TYPE,
    })
    print(f"HTTP {r.status_code}")
    data = r.json()
    if "access_token" not in data:
        print("error:", data.get("error"), "-", data.get("error_description"))
        return
    new = c.decode_jwt(data["access_token"])
    print("issued_token_type:", data.get("issued_token_type"))
    print("new token: sub =", new.get("preferred_username"),
          "| azp =", new.get("azp"), "| scope =", data.get("scope"),
          "| act =", new.get("act", "(none -> NOT delegation)"))

    c.banner("3. Delegation attempt (actor_token) - Keycloak V2 has no `act`")
    actor = s.post(c.TOKEN_URL, auth=(c.RESOURCE_CLIENT, c.RESOURCE_SECRET),
                   data={"grant_type": "client_credentials"}).json()["access_token"]
    r = s.post(c.TOKEN_URL, auth=(c.RESOURCE_CLIENT, c.RESOURCE_SECRET), data={
        "grant_type": TE_GRANT, "subject_token": subject,
        "subject_token_type": ACCESS_TOKEN_TYPE,
        "actor_token": actor, "actor_token_type": ACCESS_TOKEN_TYPE,
    })
    deleg = c.decode_jwt(r.json()["access_token"]) if "access_token" in r.json() else {}
    print("with actor_token -> act claim:", deleg.get("act", "(none)"))
    print("Confirms: Standard Token Exchange V2 = impersonation-style same-subject")
    print("exchange; the RFC 8693 `act` delegation claim is not emitted.")


if __name__ == "__main__":
    main()
