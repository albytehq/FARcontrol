#!/usr/bin/env bash
# FARcontrol SBOM (§76) — dependency inventory from cargo metadata (offline,
# lockfile-driven). Output: SPDX-style JSON in reports/sbom.json
# cargo-audit-style CVE scanning runs separately (dep-check) when possible.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/reports/sbom.json}"
mkdir -p "$ROOT/reports"
cargo metadata --format-version 1 --offline 2>/dev/null > /tmp/farcontrol-metadata.json || \
cargo metadata --format-version 1 > /tmp/farcontrol-metadata.json
python3 - "$ROOT" "$OUT" <<'PYEOF'
import json, sys, datetime, subprocess, os
root, out = sys.argv[1], sys.argv[2]
meta = json.load(open("/tmp/farcontrol-metadata.json"))
pkg = next(p for p in meta["packages"] if p["name"] == "frtrol")
deps = []
for p in meta["packages"][1:]:
    deps.append({
        "name": p["name"],
        "version": p["version"],
        "source": p.get("source", "local"),
        "license": p.get("license", "unknown"),
        "checksum": p.get("checksum"),
    })
sbom = {
    "spdxVersion": "SPDX-2.2",
    "SPDXID": "SPDXRef-Document",
    "creationInfo": {
        "created": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "creators": ["Tool: farcontrol scripts/sbom.sh"],
    },
    "name": pkg["name"],
    "versionInfo": pkg["version"],
    "documentDescribes": ["SPDXRef-Package-frtrol"],
    "packages": [
        {
            "SPDXID": "SPDXRef-Package-frtrol",
            "name": pkg["name"],
            "versionInfo": pkg["version"],
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": "MIT",
        }
    ] + [
        {
            "SPDXID": f"SPDXRef-Package-{d['name']}-{d['version']}",
            "name": d["name"],
            "versionInfo": d["version"],
            "downloadLocation": d["source"],
            "licenseConcluded": d["license"] or "NOASSERTION",
        }
        for d in deps
    ],
}
with open(out, "w") as f:
    json.dump(sbom, f, indent=2)
print(f"SBOM written: {out}")
print(f"  main package: {pkg['name']} {pkg['version']}")
print(f"  dependencies: {len(deps)} crates (from Cargo.lock via cargo metadata)")
PYEOF
