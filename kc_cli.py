#!/usr/bin/env python3
"""kc - a small Keycloak CLI for the Lecture 7 token-lifecycle flows.

One tool that exercises four Keycloak features against the lab:

  introspect   RFC 7662 - ask the issuer whether a token is active
  exchange     RFC 8693 - swap the current token (internal-to-internal)
  revoke       RFC 7009 - revoke the refresh token (must be the owning client)
  logout       RP-initiated logout - ends the session and triggers
               OIDC back-channel logout to clients that registered a URL
  bcl-listen   the other side: receive and VALIDATE the back-channel
               Logout Token Keycloak POSTs when the session ends

Tokens from `login` are cached in ~/.kc_cli_tokens.json and reused by the
other commands.

Examples:
  python kc_cli.py login                 # alice via spa-token-demo (public)
  python kc_cli.py introspect
  python kc_cli.py exchange
  python kc_cli.py revoke
  # back-channel logout, two terminals:
  python kc_cli.py bcl-listen --port 9000
  python kc_cli.py login --client bcl-demo && python kc_cli.py logout
"""
import argparse
import base64
import http.server
import json
import os
import urllib.parse

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import config as c

STATE_FILE = os.path.expanduser("~/.kc_cli_tokens.json")
BACKCHANNEL_EVENT = "http://schemas.openid.net/event/backchannel-logout"


# --- token state -------------------------------------------------------------
def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)


def client_auth(client_id):
    """Basic auth tuple for a confidential client, or None for a public one."""
    secret = c.CLIENT_SECRETS.get(client_id)
    return (client_id, secret) if secret else None


# --- JWKS / JWT verification (cryptography only, no PyJWT needed) -------------
def _b64u(data):
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


_jwks_cache = None


def jwks(s):
    global _jwks_cache
    if _jwks_cache is None:
        _jwks_cache = s.get(c.JWKS_URL).json()
    return _jwks_cache


def verify_jwt(s, token):
    """Verify an RS256 JWT against Keycloak's JWKS and return its claims."""
    h_b64, p_b64, sig_b64 = token.split(".")
    header = json.loads(_b64u(h_b64))
    key = next(k for k in jwks(s)["keys"]
               if k.get("kid") == header.get("kid") and k.get("kty") == "RSA")
    n = int.from_bytes(_b64u(key["n"]), "big")
    e = int.from_bytes(_b64u(key["e"]), "big")
    pub = rsa.RSAPublicNumbers(e, n).public_key()
    pub.verify(_b64u(sig_b64), f"{h_b64}.{p_b64}".encode(),
               padding.PKCS1v15(), hashes.SHA256())
    return json.loads(_b64u(p_b64))


# --- commands ----------------------------------------------------------------
def cmd_login(s, args):
    data = {"grant_type": "password", "client_id": args.client,
            "username": args.user, "password": args.password, "scope": args.scope}
    secret = c.CLIENT_SECRETS.get(args.client)
    if secret:
        data["client_secret"] = secret
    r = s.post(c.TOKEN_URL, data=data)
    if r.status_code != 200:
        print("login failed:", r.json()); return
    tok = r.json()
    save_state({"client_id": args.client, "access_token": tok["access_token"],
                "refresh_token": tok.get("refresh_token"),
                "id_token": tok.get("id_token")})
    claims = c.decode_jwt(tok["access_token"])
    print(f"logged in as {claims.get('preferred_username')} via {args.client}")
    print(f"  sid={claims.get('sid')}  scope={tok.get('scope')}")


def cmd_introspect(s, args):
    state = load_state()
    token = args.token or state.get("access_token")
    if not token:
        print("no token - run `login` first"); return
    r = s.post(c.INTROSPECT_URL, auth=(c.RESOURCE_CLIENT, c.RESOURCE_SECRET),
               data={"token": token})
    d = r.json()
    print("active:", d.get("active"))
    if d.get("active"):
        for k in ("username", "client_id", "scope", "token_type", "exp", "sid"):
            print(f"  {k}: {d.get(k)}")


def cmd_exchange(s, args):
    state = load_state()
    subject = state.get("access_token")
    if not subject:
        print("no token - run `login` first"); return
    r = s.post(c.TOKEN_URL, auth=(c.RESOURCE_CLIENT, c.RESOURCE_SECRET), data={
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": subject,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
    })
    d = r.json()
    if "access_token" not in d:
        print("exchange failed:", d.get("error"), "-", d.get("error_description"))
        if d.get("error") == "access_denied":
            print("hint: the subject token must list", c.RESOURCE_CLIENT,
                  "in aud (login via spa-token-demo, which has the audience mapper).")
        return
    new = c.decode_jwt(d["access_token"])
    print("exchanged ok:")
    print(f"  sub={new.get('preferred_username')}  azp={new.get('azp')}"
          f"  scope={d.get('scope')}  act={new.get('act', '(none)')}")


def cmd_revoke(s, args):
    state = load_state()
    token = state.get("refresh_token") if args.kind == "refresh" else state.get("access_token")
    client = state.get("client_id")
    if not token or not client:
        print("no token - run `login` first"); return
    data = {"client_id": client, "token": token, "token_type_hint": f"{args.kind}_token"}
    auth = client_auth(client)
    if auth:
        data.pop("client_id")
    r = s.post(c.REVOKE_URL, data=data, auth=auth)
    print(f"revoke {args.kind} token -> HTTP {r.status_code}",
          "(RFC 7009: 200 even if already invalid)" if r.status_code == 200 else r.text)


def cmd_logout(s, args):
    state = load_state()
    client = state.get("client_id")
    refresh = state.get("refresh_token")
    if not refresh or not client:
        print("no session - run `login` first"); return

    if args.admin:
        # Simulate "the session was ended elsewhere" (admin disables it, or the
        # user logged out on another device). THIS is what makes Keycloak send a
        # back-channel Logout Token to the still-registered client - a client is
        # never notified of a logout it initiated itself.
        sub = c.decode_jwt(state["access_token"])["sub"]
        at = c.admin_token(s)
        r = s.post(f"{c.ADMIN_BASE}/users/{sub}/logout",
                   headers={"Authorization": f"Bearer {at}"})
        print(f"admin-initiated logout of user {sub} -> HTTP {r.status_code}")
        print("Keycloak now POSTs a back-channel Logout Token to every client in")
        print("that session that registered a backchannel.logout.url.")
        return

    data = {"client_id": client, "refresh_token": refresh}
    secret = c.CLIENT_SECRETS.get(client)
    if secret:
        data["client_secret"] = secret
    r = s.post(c.LOGOUT_URL, data=data)
    print(f"RP-initiated logout -> HTTP {r.status_code}")
    print("Session ended for this client. Note: a client is not back-channel")
    print("notified of a logout it started itself - use --admin to see the token.")


class BclHandler(http.server.BaseHTTPRequestHandler):
    session = None  # the requests session, set on the class before serving

    def do_GET(self):  # noqa: N802
        self.send_response(200); self.end_headers()
        self.wfile.write(b"bcl-listen: ready")

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        params = urllib.parse.parse_qs(body)
        token = (params.get("logout_token") or [None])[0]
        self.send_response(200); self.end_headers()
        print("\n--- back-channel logout received ---")
        if not token:
            print("no logout_token in request body"); return
        try:
            claims = verify_jwt(BclHandler.session, token)
        except Exception as e:  # noqa: BLE001
            print("SIGNATURE INVALID - rejecting:", e); return
        ok_event = BACKCHANNEL_EVENT in (claims.get("events") or {})
        no_nonce = "nonce" not in claims
        print("signature: VALID")
        print("  iss:", claims.get("iss"))
        print("  aud:", claims.get("aud"))
        print("  sub:", claims.get("sub"), " sid:", claims.get("sid"))
        print("  backchannel-logout event present:", ok_event)
        print("  no nonce (required for logout tokens):", no_nonce)
        print("  -> validated; an RP would now terminate this user's local session")

    def log_message(self, *_):
        pass


def cmd_bcl_listen(s, args):
    import sys
    sys.stdout.reconfigure(line_buffering=True)  # so output shows when piped
    BclHandler.session = s
    jwks(s)  # warm the cache so verification is offline-fast
    server = http.server.HTTPServer(("0.0.0.0", args.port), BclHandler)
    print(f"bcl-listen on 0.0.0.0:{args.port} (Keycloak should POST to {c.BCL_URL})")
    print("Waiting for a back-channel Logout Token... Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


def main():
    p = argparse.ArgumentParser(description="Keycloak token-lifecycle CLI (Lecture 7)")
    sub = p.add_subparsers(dest="cmd", required=True)

    lp = sub.add_parser("login", help="get tokens (password grant) and cache them")
    lp.add_argument("--client", default=c.PUBLIC_CLIENT)
    lp.add_argument("--user", default=c.DEMO_USER)
    lp.add_argument("--password", default=c.DEMO_PASS)
    lp.add_argument("--scope", default="openid")

    ip = sub.add_parser("introspect", help="RFC 7662 introspection")
    ip.add_argument("--token", help="token to introspect (default: cached access token)")

    sub.add_parser("exchange", help="RFC 8693 token exchange")

    rp = sub.add_parser("revoke", help="RFC 7009 revocation")
    rp.add_argument("--kind", choices=["refresh", "access"], default="refresh")

    lo = sub.add_parser("logout", help="end the session (RP-initiated, or --admin)")
    lo.add_argument("--admin", action="store_true",
                    help="end the session via admin API (triggers back-channel logout)")

    bp = sub.add_parser("bcl-listen", help="receive + validate back-channel logout tokens")
    bp.add_argument("--port", type=int, default=9000)

    args = p.parse_args()
    c.require_lab()
    s = c.session()
    {"login": cmd_login, "introspect": cmd_introspect, "exchange": cmd_exchange,
     "revoke": cmd_revoke, "logout": cmd_logout, "bcl-listen": cmd_bcl_listen}[args.cmd](s, args)


if __name__ == "__main__":
    main()
