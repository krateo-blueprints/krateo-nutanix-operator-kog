#!/usr/bin/env python3
"""Self-test for hack/validate-oas-sources.py: runs the real script against generated trees.

Each case builds a temporary repository with oas/_official/ and oas/SOURCES.yaml, runs the validator on
it, and checks the verdict and a line of its output. The base case passes, and each mutation of it must
be refused for its own reason: one changed byte, an unlisted file, an entry without a file, an empty
manifest, a missing manifest, a url naming another namespace, a malformed sha256, and an empty
oas/_official/. Then the same checks run on this repository itself.

Run from the repository root: python3 hack/test-validate-oas-sources.py
"""
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "validate-oas-sources.py")
ROOT = os.path.dirname(HERE)

BASE = {
    "alpha-v4.0.yaml": b"openapi: 3.0.1\ninfo:\n  version: \"4.0\"\n",
    "beta-v4.0.a3.yaml": b"openapi: 3.0.1\ninfo:\n  version: \"4.0.a3\"\n",
}


def entry(name, data, ns=None, ver=None, sha=None):
    base = name[:-5]
    n, v = base.split("-v", 1)
    ns, ver = ns or n, ver or "v" + v
    return [
        "  %s:" % name,
        "    url: https://developers.nutanix.com/api/v1/namespaces/%s/versions/%s/yaml" % (ns, ver),
        "    version: %s" % ver,
        "    sha256: %s" % (sha or hashlib.sha256(data).hexdigest()),
    ]


def manifest(entries):
    return "verified: \"2026-11-18\"\nfiles:\n" + "".join(l + "\n" for e in entries for l in e)


def tree(files, manifest_text):
    root = tempfile.mkdtemp()
    os.makedirs(os.path.join(root, "oas", "_official"))
    for name, data in files.items():
        open(os.path.join(root, "oas", "_official", name), "wb").write(data)
    if manifest_text is not None:
        open(os.path.join(root, "oas", "SOURCES.yaml"), "w").write(manifest_text)
    return root


def base_entries(files=BASE):
    return [entry(n, d) for n, d in sorted(files.items())]


def changed_byte():
    files = dict(BASE)
    data = bytearray(files["alpha-v4.0.yaml"])
    data[-2] ^= 0x01
    return dict(files, **{"alpha-v4.0.yaml": bytes(data)}), manifest(base_entries())


CASES = [
    # (name, (files, manifest text or None), passes?, text the output must contain)
    ("base tree", (BASE, manifest(base_entries())), True, "2 of 2 vendored spec(s) match oas/SOURCES.yaml, 0 problem(s)"),
    ("one changed byte", changed_byte(), False, "alpha-v4.0.yaml: sha256 is"),
    ("unlisted file", (dict(BASE, **{"gamma-v4.0.yaml": b"x\n"}), manifest(base_entries())), False,
     "oas/_official/gamma-v4.0.yaml has no entry"),
    ("entry without file", ({"alpha-v4.0.yaml": BASE["alpha-v4.0.yaml"]}, manifest(base_entries())), False,
     "lists beta-v4.0.a3.yaml, which is not in oas/_official/"),
    ("empty manifest", (BASE, "verified: \"2026-11-18\"\nfiles:\n"), False, "lists no files, so nothing was checked"),
    ("manifest with no keys", (BASE, ""), False, "lists no files, so nothing was checked"),
    ("missing manifest", (BASE, None), False, "oas/SOURCES.yaml is missing"),
    ("url names another namespace", (BASE, manifest([entry("alpha-v4.0.yaml", BASE["alpha-v4.0.yaml"], ns="prism"),
                                                     entry("beta-v4.0.a3.yaml", BASE["beta-v4.0.a3.yaml"])])), False,
     "do not name this file's namespace and version"),
    ("url names another version", (BASE, manifest([entry("alpha-v4.0.yaml", BASE["alpha-v4.0.yaml"], ver="v4.2"),
                                                   entry("beta-v4.0.a3.yaml", BASE["beta-v4.0.a3.yaml"])])), False,
     "do not name this file's namespace and version"),
    ("malformed sha256", (BASE, manifest([entry("alpha-v4.0.yaml", BASE["alpha-v4.0.yaml"], sha="ABC"),
                                          entry("beta-v4.0.a3.yaml", BASE["beta-v4.0.a3.yaml"])])), False,
     "is not 64 lowercase hex characters"),
    ("no spec files", ({}, manifest(base_entries())), False, "oas/_official/ holds no files"),
]


def run(root):
    p = subprocess.run([sys.executable, "-I", SCRIPT, root], capture_output=True, text=True,
                       env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    return p.returncode == 0, p.stdout + p.stderr


def main():
    failures = 0
    for name, (files, text), want_ok, want in CASES:
        root = tree(files, text)
        try:
            ok, out = run(root)
        finally:
            shutil.rmtree(root)
        good = ok == want_ok and want in out
        failures += not good
        print("%s  %-28s exit=%s  (want %s, %r)" % ("ok  " if good else "FAIL", name, "0" if ok else "1",
                                                    "success" if want_ok else "failure", want))
        if not good:
            print("      output: " + out.strip().replace("\n", "\n              "))
    ok, out = run(ROOT)
    failures += not ok
    print("%s  this repository              %s" % ("ok  " if ok else "FAIL", out.strip().splitlines()[-1] if out.strip() else "(no output)"))
    if not ok:
        print("      output: " + out.strip().replace("\n", "\n              "))
    print("%d case(s) and this repository, %d failure(s)" % (len(CASES), failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
