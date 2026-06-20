"""RFC 8252 - OAuth 2.0 for Native Apps (Authorization Code + PKCE, loopback).

A native/desktop/CLI app is a PUBLIC client - it cannot keep a secret. RFC 8252
says: use the system browser (not an embedded WebView), Authorization Code with
PKCE (RFC 7636), and a redirect the OS can route back to the app. This demo uses
the loopback interface (http://127.0.0.1:<random port>/callback), the
recommended redirect for desktop/CLI apps.

This flow needs a human to log in, so it is INTERACTIVE - it opens your browser.

Run:  python native_app_pkce_demo.py
"""
import base64
import hashlib
import http.server
import os
import secrets
import threading
import urllib.parse
import webbrowser

import config as c


def pkce_pair():
    verifier = base64.urlsafe_b64encode(os.urandom(40)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


class CatchCode(http.server.BaseHTTPRequestHandler):
    code = None
    state = None

    def do_GET(self):  # noqa: N802
        q = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(q)
        CatchCode.code = params.get("code", [None])[0]
        CatchCode.state = params.get("state", [None])[0]
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<h3>You can close this tab and return to the terminal.</h3>")

    def log_message(self, *_):  # silence
        pass


def main():
    c.require_lab()
    s = c.session()

    # Bind a loopback server on a random free port.
    server = http.server.HTTPServer(("127.0.0.1", 0), CatchCode)
    port = server.server_address[1]
    redirect_uri = f"http://127.0.0.1:{port}/callback"

    verifier, challenge = pkce_pair()
    state = secrets.token_urlsafe(16)

    auth = c.AUTH_URL + "?" + urllib.parse.urlencode({
        "client_id": c.NATIVE_CLIENT,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": "openid profile",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })

    c.banner("1. Open the system browser to the authorization endpoint")
    print("Redirect URI (loopback):", redirect_uri)
    print("PKCE: sending code_challenge (S256); the verifier never leaves the app.")
    print("\nIf the browser does not open, paste this URL:\n", auth)
    threading.Thread(target=server.handle_request, daemon=True).start()
    webbrowser.open(auth)

    c.banner("2. Waiting for the redirect with the authorization code...")
    server.serve_forever() if False else None
    # handle_request above serves exactly one request; wait for it
    while CatchCode.code is None and CatchCode.state is None:
        pass
    if CatchCode.state != state:
        print("state mismatch - aborting (possible CSRF)")
        return
    print("got authorization code:", (CatchCode.code or "")[:12], "...")

    c.banner("3. Exchange code + PKCE verifier for tokens (no client secret)")
    r = s.post(c.TOKEN_URL, data={
        "grant_type": "authorization_code",
        "client_id": c.NATIVE_CLIENT,
        "code": CatchCode.code,
        "redirect_uri": redirect_uri,
        "code_verifier": verifier,
    })
    print(f"HTTP {r.status_code}")
    tok = r.json()
    if "access_token" in tok:
        who = c.decode_jwt(tok["access_token"])
        print("TOKENS ISSUED -> sub:", who.get("preferred_username"),
              "| azp:", who.get("azp"), "| scope:", tok.get("scope"))
        print("\nNo client secret was used - PKCE proved the same app that started")
        print("the flow finished it. That is the native-app pattern (RFC 8252).")
    else:
        print("error:", tok.get("error"), "-", tok.get("error_description"))


if __name__ == "__main__":
    main()
