"""Guest-agent entry point for the demo certificate. Payload arrives on stdin."""

import hashlib
import json
import os
import pwd
import shutil
import ssl
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


PKI = Path("/etc/demo-agent/pki")
CERT = PKI / "demo-agent.crt"
KEY = PKI / "demo-agent.key"
MIN_REMAINING_SECONDS = 30 * 24 * 60 * 60


def run(*args):
    return subprocess.run(args, capture_output=True, check=False)


def fingerprint(path):
    pem = path.read_text(encoding="ascii")
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()


def safe_regular(path):
    return path.is_file() and not path.is_symlink() and stat.S_ISREG(path.stat().st_mode) and path.stat().st_nlink == 1


def ready():
    if not safe_regular(CERT) or not safe_regular(KEY):
        return {"ready": False}
    subject = run("openssl", "x509", "-in", str(CERT), "-noout", "-subject", "-nameopt", "RFC2253")
    cert_pub = run("openssl", "x509", "-in", str(CERT), "-pubkey", "-noout")
    key_pub = run("openssl", "pkey", "-in", str(KEY), "-pubout")
    if (subject.returncode or subject.stdout.strip() != b"subject=CN=demo-agent"
            or cert_pub.returncode or key_pub.returncode or cert_pub.stdout != key_pub.stdout):
        return {"ready": False}
    if run("openssl", "x509", "-in", str(CERT), "-noout", "-checkend", str(MIN_REMAINING_SECONDS)).returncode:
        return {"ready": False}
    return {"ready": True, "fingerprint": fingerprint(CERT)}


def validate(cert, key, ca):
    subject = run("openssl", "x509", "-in", str(cert), "-noout", "-subject", "-nameopt", "RFC2253")
    if subject.returncode or subject.stdout.strip() != b"subject=CN=demo-agent":
        raise ValueError("unexpected certificate identity")
    if run("openssl", "verify", "-CAfile", str(ca), str(cert)).returncode:
        raise ValueError("certificate chain failed")
    if run("openssl", "x509", "-in", str(cert), "-noout", "-checkend", str(MIN_REMAINING_SECONDS)).returncode:
        raise ValueError("certificate lifetime too short")
    cert_pub = run("openssl", "x509", "-in", str(cert), "-pubkey", "-noout")
    key_pub = run("openssl", "pkey", "-in", str(key), "-pubout")
    if cert_pub.returncode or key_pub.returncode or cert_pub.stdout != key_pub.stdout:
        raise ValueError("certificate and key do not match")


def install():
    if os.geteuid() != 0 or not PKI.is_dir() or PKI.is_symlink():
        raise ValueError("unsafe certificate destination")
    if not safe_regular(CERT) or not safe_regular(KEY):
        raise ValueError("unsafe existing certificate files")
    if stat.S_IMODE(KEY.stat().st_mode) & 0o077:
        raise ValueError("unsafe existing private key")
    payload = json.load(sys.stdin)
    if set(payload) != {"cert", "key", "ca"}:
        raise ValueError("invalid certificate payload")
    user = pwd.getpwnam("demo-agent")
    if CERT.stat().st_uid != user.pw_uid or KEY.stat().st_uid != user.pw_uid:
        raise ValueError("unsafe existing certificate ownership")
    with tempfile.TemporaryDirectory(prefix=".renew-", dir=PKI) as temporary:
        work = Path(temporary)
        incoming = {}
        for field, name in (("cert", "new.crt"), ("key", "new.key"), ("ca", "root-ca.crt")):
            value = payload[field]
            if not isinstance(value, str) or len(value) > 65536:
                raise ValueError("invalid certificate payload")
            path = work / name
            path.write_text(value, encoding="ascii")
            path.chmod(0o600)
            incoming[field] = path
        validate(incoming["cert"], incoming["key"], incoming["ca"])
        expected = fingerprint(incoming["cert"])
        for field in ("cert", "key"):
            os.chown(incoming[field], user.pw_uid, user.pw_gid)
        old_cert, old_key = work / "old.crt", work / "old.key"
        shutil.copy2(CERT, old_cert)
        shutil.copy2(KEY, old_key)
        try:
            os.replace(incoming["cert"], CERT)
            os.replace(incoming["key"], KEY)
            if fingerprint(CERT) != expected:
                raise ValueError("certificate activation failed")
        except Exception:
            os.replace(old_cert, CERT)
            os.replace(old_key, KEY)
            raise
    return {"installed": True, "fingerprint": expected}


def main():
    try:
        if len(sys.argv) != 2 or sys.argv[1] not in {"check", "install"}:
            raise ValueError("invalid operation")
        result = ready() if sys.argv[1] == "check" else install()
        print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        print(json.dumps({"error": "certificate operation failed"}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
