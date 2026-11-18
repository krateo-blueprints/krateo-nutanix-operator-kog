#!/usr/bin/env python3
"""Refuse any drift between oas/_official/ and the provenance manifest oas/SOURCES.yaml.

Every file in oas/_official/ is a Nutanix spec vendored byte for byte. The manifest records, per file,
the upstream URL, the API version and the sha256 of the committed bytes. This check fails when:
  - the manifest is missing, unparsable, or lists no files (a gate with no input checks nothing);
  - an entry is malformed: no url, a url that does not name the file's own namespace and version, or a
    sha256 that is not 64 lowercase hex characters;
  - a file's sha256 differs from its entry (the file was edited, or re-vendored without the manifest);
  - a file in oas/_official/ has no entry, or an entry has no file.

Why: .trivyignore.yaml exempts Trivy's aws-access-key-id rule for oas/_official/prism-v4.0.yaml, where
Nutanix's published spec carries an access-key example. A Trivy ignore cannot match on a value, so the
exemption would also cover a key added to that file later. Pinning the bytes makes that impossible
without a reviewed manifest change.

Usage: validate-oas-sources.py [repo-root]   (default: the current directory)
"""
import hashlib
import os
import re
import sys

import yaml

URL = re.compile(r"^https://developers\.nutanix\.com/api/v1/namespaces/([a-z0-9]+)/versions/(v[0-9][0-9a-z.]*)/yaml$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
NAME = re.compile(r"^([a-z0-9]+)-(v[0-9][0-9a-z.]*)\.yaml$")


def main(root):
    spec_dir = os.path.join(root, "oas", "_official")
    manifest_path = os.path.join(root, "oas", "SOURCES.yaml")
    errors = []

    if not os.path.isfile(manifest_path):
        print("::error::oas/SOURCES.yaml is missing, so no vendored spec is pinned")
        return 1
    try:
        manifest = yaml.safe_load(open(manifest_path, encoding="utf-8"))
    except yaml.YAMLError as e:
        print("::error::oas/SOURCES.yaml does not parse: %s" % e)
        return 1
    entries = (manifest or {}).get("files") if isinstance(manifest, dict) else None
    if not isinstance(entries, dict) or not entries:
        print("::error::oas/SOURCES.yaml lists no files, so nothing was checked")
        return 1

    present = sorted(os.listdir(spec_dir)) if os.path.isdir(spec_dir) else []
    present = [f for f in present if os.path.isfile(os.path.join(spec_dir, f))]
    if not present:
        errors.append("oas/_official/ holds no files, but the manifest lists %d" % len(entries))

    for name in present:
        if name not in entries:
            errors.append("oas/_official/%s has no entry in oas/SOURCES.yaml" % name)
    for name in sorted(entries):
        if name not in present:
            errors.append("oas/SOURCES.yaml lists %s, which is not in oas/_official/" % name)

    verified = 0
    for name in sorted(set(present) & set(entries)):
        entry = entries[name] if isinstance(entries[name], dict) else {}
        url, sha = str(entry.get("url", "")), str(entry.get("sha256", ""))
        n, u = NAME.match(name), URL.match(url)
        if not u:
            errors.append("%s: url %r is not a developers.nutanix.com spec URL" % (name, url))
        elif not n or u.groups() != n.groups() or str(entry.get("version", "")) != u.group(2):
            errors.append("%s: url %r and version %r do not name this file's namespace and version" % (name, url, entry.get("version")))
        if not SHA256.match(sha):
            errors.append("%s: sha256 %r is not 64 lowercase hex characters" % (name, sha))
            continue
        actual = hashlib.sha256(open(os.path.join(spec_dir, name), "rb").read()).hexdigest()
        if actual != sha:
            errors.append("%s: sha256 is %s, but oas/SOURCES.yaml pins %s; the vendored bytes changed. "
                          "Re-vendor from the url and update the entry in the same change, or revert the edit" % (name, actual, sha))
            continue
        verified += 1

    for e in errors:
        print("::error::" + e)
    print("%d of %d vendored spec(s) match oas/SOURCES.yaml, %d problem(s)" % (verified, len(present), len(errors)))
    return 1 if errors or verified == 0 else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "."))
