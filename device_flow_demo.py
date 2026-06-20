"""RFC 8628 - Device Authorization Grant (for CLI / TV / IoT clients).

The device has no browser or keyboard. It asks Keycloak for a pair of codes,
shows the user a short user_code + URL, and polls the token endpoint while the
user approves on a second device (phone/laptop).

By default this is the real UX: it prints the URL and code and waits for you to
approve in a browser. With `--auto-approve` it drives the approval headlessly
using a username/password (handy for testing/CI in the lab).

Run (interactive):  python device_flow_demo.py
Run (headless):     python device_flow_demo.py --auto-approve
"""
import re
import sys
import time
from urllib.parse import urljoin

import config as c

DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


def start(s):
    r = s.post(c.DEVICE_URL, data={"client_id": c.DEVICE_CLIENT, "scope": "openid"})
    r.raise_for_status()
    return r.json()


def auto_approve(s, verification_uri_complete, username, password):
    """Drive Keycloak's verification pages like a browser would (lab testing)."""
    def form_action(html, base):
        m = re.search(r'<form[^>]*action="([^"]+)"', html)
        return urljoin(base, m.group(1).replace("&amp;", "&")) if m else None

    resp = s.get(verification_uri_complete)
    resp = s.post(form_action(resp.text, resp.url),
                  data={"username": username, "password": password})
    # device confirmation / consent page -> accept
    action = form_action(resp.text, resp.url)
    if action:
        s.post(action, data={"accept": "Yes"})


def poll(s, device_code, interval, expires_in):
    deadline = time.time() + expires_in
    while time.time() < deadline:
        r = s.post(c.TOKEN_URL, data={"grant_type": DEVICE_GRANT,
                   "client_id": c.DEVICE_CLIENT, "device_code": device_code}).json()
        if "access_token" in r:
            return r
        err = r.get("error")
        if err == "authorization_pending":
            pass
        elif err == "slow_down":
            interval += 5  # RFC 8628: back off by 5s
        else:  # access_denied / expired_token / invalid_grant
            print("stopped:", err)
            return None
        print(f"  ... {err}, waiting {interval}s")
        time.sleep(interval)
    print("stopped: device_code expired")
    return None


def main():
    c.require_lab()
    s = c.session()

    c.banner("1. Device requests codes")
    d = start(s)
    print("user_code:        ", d["user_code"])
    print("verification_uri: ", d["verification_uri"])
    print("expires_in:       ", d["expires_in"], "s")
    print("interval:         ", d["interval"], "s")

    if "--auto-approve" in sys.argv:
        c.banner("2. Headless approval (lab testing)")
        auto_approve(c.session(), d["verification_uri_complete"], c.DEMO_USER, c.DEMO_PASS)
        print("approved as", c.DEMO_USER)
    else:
        c.banner("2. Approve in a browser")
        print(f"Open {d['verification_uri']} and enter: {d['user_code']}")
        print(f"(or open directly: {d['verification_uri_complete']})")

    c.banner("3. Poll the token endpoint")
    tok = poll(s, d["device_code"], d["interval"], d["expires_in"])
    if tok:
        who = c.decode_jwt(tok["access_token"])
        print("\nTOKENS ISSUED -> sub:", who.get("preferred_username"),
              "| azp:", who.get("azp"), "| scope:", tok.get("scope"))


if __name__ == "__main__":
    main()
