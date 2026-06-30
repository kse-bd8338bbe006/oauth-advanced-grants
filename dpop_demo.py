#!/usr/bin/env python3
"""
DPoP - Demonstrating Proof-of-Possession (RFC 9449), live against the lab.

Sender-constrained tokens are a Lecture 8 topic, but the mechanism is pure
token-endpoint behaviour, so it lives here with the other grant/endpoint demos.

What it proves, end to end, against the real Keycloak:
  1. A token request carrying a DPoP proof returns token_type=DPoP and an access
     token whose cnf.jkt equals the RFC 7638 thumbprint of OUR public key.
  2. The SAME client without a DPoP header returns a plain Bearer token (no cnf)
     - DPoP is exactly what turns a bearer token into a sender-constrained one.
  3. A DPoP proof with the wrong htu is rejected (invalid_request, URL mismatch).

The ES256 proof JWT is built by hand (no PyJWT) so every field is visible.
Reuses the confidential client `documents-api` via client_credentials.

Run:  python dpop_demo.py
"""
import base64
import calendar
import email.utils
import hashlib
import json
import sys
import time
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

import config as C

CLIENT = C.RESOURCE_CLIENT
SECRET = C.RESOURCE_SECRET


# --- JOSE helpers (ES256 / P-256), no external JWT lib ------------------------
def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def public_jwk(pub: ec.EllipticCurvePublicKey) -> dict:
    n = pub.public_numbers()
    return {"kty": "EC", "crv": "P-256",
            "x": b64url(n.x.to_bytes(32, "big")),
            "y": b64url(n.y.to_bytes(32, "big"))}


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638: SHA-256 over the canonical JWK (required members, sorted, no space)."""
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
        separators=(",", ":"), sort_keys=True,
    ).encode()
    return b64url(hashlib.sha256(canonical).digest())


def es256_sign(signing_input: bytes, priv: ec.EllipticCurvePrivateKey) -> bytes:
    r, s = decode_dss_signature(priv.sign(signing_input, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")  # JOSE raw r||s


def make_dpop_proof(priv, jwk, htm, htu, iat, nonce=None, ath=None) -> str:
    header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
    payload = {"htm": htm, "htu": htu, "iat": iat, "jti": uuid.uuid4().hex}
    if nonce:
        payload["nonce"] = nonce
    if ath:
        payload["ath"] = ath
    si = (b64url(json.dumps(header, separators=(",", ":")).encode()) + "." +
          b64url(json.dumps(payload, separators=(",", ":")).encode())).encode()
    return si.decode() + "." + b64url(es256_sign(si, priv))


def kc_clock_offset(s) -> int:
    """(local - KC) seconds, so the proof iat lands inside KC's acceptance window.

    The lab VMs drift after the laptop sleeps; without this the proof can be
    rejected as 'DPoP proof is not active'.
    """
    r = s.get(C.OIDC.replace("/protocol/openid-connect", "/.well-known/openid-configuration"))
    kc = calendar.timegm(email.utils.parsedate(r.headers["Date"]))
    return int(time.time()) - kc


# --- token request with DPoP nonce handling ----------------------------------
def request_token(s, offset, priv=None, jwk=None, htu=C.TOKEN_URL):
    data = {"grant_type": "client_credentials", "client_id": CLIENT, "client_secret": SECRET}
    headers, nonce = {}, None
    for _ in range(2):  # retry once if KC demands a nonce
        if priv is not None:
            headers["DPoP"] = make_dpop_proof(priv, jwk, "POST", htu,
                                              iat=int(time.time()) - offset, nonce=nonce)
        r = s.post(C.TOKEN_URL, data=data, headers=headers)
        body = r.json() if r.text else {}
        if r.status_code == 400 and body.get("error") == "use_dpop_nonce":
            nonce = r.headers.get("DPoP-Nonce")
            print(f"   (KC asked for a nonce: {nonce[:16]}... - retrying)")
            continue
        return r.status_code, body
    return r.status_code, body


def main():
    C.require_lab()
    C.banner("DPoP (RFC 9449) - sender-constrained tokens")
    print(f"KC: {C.KC_BASE}  realm: {C.REALM}  client: {CLIENT}")

    s = C.session()
    offset = kc_clock_offset(s)
    print(f"clock skew (laptop - KC) = {offset}s -> aligning DPoP iat to KC's clock")

    priv = ec.generate_private_key(ec.SECP256R1())
    jwk = public_jwk(priv.public_key())
    our_jkt = jwk_thumbprint(jwk)
    print(f"our JWK thumbprint (jkt): {our_jkt}")

    passed = True

    print("\n[1] token request WITH a DPoP proof")
    status, body = request_token(s, offset, priv, jwk)
    if status != 200:
        print(f"   FAIL - HTTP {status}: {body}")
        sys.exit(1)
    ttype = body.get("token_type", "")
    cnf = C.decode_jwt(body["access_token"]).get("cnf", {})
    print(f"   token_type = {ttype}")
    print(f"   access_token cnf.jkt = {cnf.get('jkt')}")
    ok = ttype.lower() == "dpop" and cnf.get("jkt") == our_jkt
    print(f"   {'PASS' if ok else 'FAIL'}: DPoP-bound and cnf.jkt == our thumbprint")
    passed &= ok

    print("\n[2] token request WITHOUT a DPoP proof (control)")
    status, body = request_token(s, offset)
    ttype = body.get("token_type", "")
    cnf = C.decode_jwt(body["access_token"]).get("cnf") if status == 200 else "n/a"
    print(f"   token_type = {ttype}   cnf = {cnf}")
    ok = status == 200 and ttype.lower() == "bearer" and not cnf
    print(f"   {'PASS' if ok else 'FAIL'}: same client returns a plain Bearer token")
    passed &= ok

    print("\n[3] DPoP proof with a WRONG htu (must be rejected)")
    status, body = request_token(s, offset, priv, jwk, htu="https://evil.example/token")
    err, desc = body.get("error"), body.get("error_description", "")
    ok = status == 400 and "dpop" in f"{err} {desc}".lower()
    print(f"   HTTP {status}  error = {err}  ({desc})")
    print(f"   {'PASS' if ok else 'FAIL'}: KC rejects a proof whose htu does not match")
    passed &= ok

    C.banner("ALL CHECKS PASSED" if passed else "SOME CHECKS FAILED")
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
