#!/usr/bin/env python3
"""Shrink `cargo metadata --format-version 1` output into a test fixture.

Keeps only what cargo-cbom reads (package names, versions, sources, targets,
the resolved graph and features) and replaces local paths, so fixtures are
small and do not leak the machine they were made on.

Usage: python3 make_fixture.py metadata.json > tests/fixtures/NAME.json
"""

import json
import re
import sys

KEEP_PACKAGE = ["name", "version", "id", "source", "manifest_path", "targets", "features", "edition"]
KEEP_TARGET = ["name", "kind", "crate_types", "src_path", "edition"]


def scrub(value):
    """Replace absolute local paths with stable placeholders."""
    if isinstance(value, str):
        value = re.sub(r"/[^\s\"]*?/registry/src/[^/]+/", "/registry/", value)
        value = re.sub(r"(path\+file://)?/(tmp|home|root|Users)/[^\s\"#)]*/(p_[A-Za-z0-9_]+)", r"\1/project/\3", value)
        return value
    if isinstance(value, list):
        return [scrub(v) for v in value]
    if isinstance(value, dict):
        return {k: scrub(v) for k, v in value.items()}
    return value


def main(path):
    with open(path) as f:
        meta = json.load(f)
    packages = []
    for p in meta["packages"]:
        q = {k: p[k] for k in KEEP_PACKAGE if k in p}
        q["dependencies"] = []
        q["targets"] = [{k: t[k] for k in KEEP_TARGET if k in t} for t in p.get("targets", [])]
        packages.append(q)
    out = {
        "packages": packages,
        "workspace_members": meta["workspace_members"],
        "workspace_default_members": meta.get("workspace_default_members", meta["workspace_members"]),
        "resolve": meta["resolve"],
        "target_directory": "/project/target",
        "version": meta["version"],
        "workspace_root": meta["workspace_root"],
        "metadata": None,
    }
    json.dump(scrub(out), sys.stdout, separators=(",", ":"), sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main(sys.argv[1])
