#!/usr/bin/env bash
# =============================================================================
# generate-sbom.sh - Generates an SPDX SBOM in a Linux container
# =============================================================================
# Linux counterpart of generate-sbom.ps1. Scans the workspace for LabVIEW project
# dependencies (such as .vipc or .vip files), generates an SPDX 2.3 JSON document,
# writes sbom.json into ci-out/sbom/results/, and outputs a fallback index.html.
#
# Usage (inside container, workspace mounted at /workspace):
#   bash /workspace/.github/labview/generate-sbom.sh /workspace /workspace/ci-out/sbom/results
# =============================================================================
set -uo pipefail

WORKSPACE_ROOT="${1:-/workspace}"
REPORT_DIR="${2:-/report}"

mkdir -p "$REPORT_DIR"

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is required by generate-sbom.sh but was not found in the container." >&2
  echo "       Add python3 to the Linux worker image (labview-ci.Dockerfile-linux)." >&2
  exit 1
fi

echo "=== Generate LabVIEW Software Bill of Materials (Linux) ==="
echo "  Workspace : $WORKSPACE_ROOT"
echo "  Report Dir: $REPORT_DIR"
echo ""

export WORKSPACE_ROOT REPORT_DIR

python3 - <<'PY'
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

workspace = Path(os.environ["WORKSPACE_ROOT"]).resolve()
report_dir = Path(os.environ["REPORT_DIR"]).resolve()
report_dir.mkdir(parents=True, exist_ok=True)

TOOLING_DIR = re.compile(r"(^|/)(\.github|actions|ci-out|build)/")

print("--- Scanning for VIPC dependency files ---")
packages = []
vipc_files = [
    p for p in workspace.rglob("*.vipc")
    if not TOOLING_DIR.search(str(p).replace("\\", "/"))
]

for vipc in vipc_files:
    vipc_rel = vipc.relative_to(workspace)
    print("  Parsing: %s" % vipc_rel)
    try:
        content = vipc.read_text(encoding="utf-8", errors="ignore").splitlines()
        for line in content:
            line = line.strip()
            # Match standard VIPC package lines formatted as "PackageName=Version"
            m = re.match(r"^(?P<name>[^=]+)=(?P<version>[^\r\n]+)", line)
            if m:
                packages.append({
                    "name": m.group("name").strip(),
                    "version": m.group("version").strip(),
                    "vendor": "VIPM Package",
                    "source_file": str(vipc_rel).replace("\\", "/"),
                })
    except Exception as err:
        print("  Error reading %s: %s" % (vipc_rel, err), file=sys.stderr)

# Construct standard SPDX 2.3 JSON model
sbom_data = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": os.environ.get("GITHUB_REPOSITORY", "LabVIEW-Project"),
    "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "creators": ["Tool: LabVIEW-CI-SBOM-Generator"],
    "packages": packages,
}

sbom_file = report_dir / "sbom.json"
sbom_file.write_text(json.dumps(sbom_data, indent=2, ensure_ascii=False), encoding="utf-8")
print("  Generated %s (%d package(s) found)" % (sbom_file, len(packages)))

# Fallback index.html report
repo = os.environ.get("GITHUB_REPOSITORY", "")
sha = os.environ.get("GITHUB_SHA", "")
short = sha[:7]
ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

pkg_rows = "".join(
    f"<tr><td><code>{p['name']}</code></td><td>{p['version']}</td><td>{p['vendor']}</td></tr>"
    for p in packages
) if packages else "<tr><td colspan='3' style='text-align:center;'>No packages found.</td></tr>"

html = (
    "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\">"
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
    "<title>Software Bill of Materials (Linux)</title>"
    f"<script>window.LVCI={{context:'sbom-report',repo:'{repo}',pagesUrl:'../../..',sha:'{sha}',short:'{short}',platform:'linux'}};</script>"
    "<script src=\"../../../lvci-header.js\" defer></script>"
    "<style>:root{--bg:#0d1117;--surface:#161b22;--border:#30363d;--fg:#e6edf3;--fg-muted:#8b949e}"
    "@media(prefers-color-scheme:light){:root{--bg:#fff;--surface:#f6f8fa;--border:#d0d7de;--fg:#1f2328;--fg-muted:#57606a}}"
    "body{margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--fg)}"
    ".wrap{max-width:1180px;margin:0 auto;padding:20px}"
    "table{width:100%;border-collapse:collapse;margin-top:16px;background:var(--surface);border:1px solid var(--border);border-radius:6px;overflow:hidden}"
    "th,td{padding:10px 14px;border-bottom:1px solid var(--border);text-align:left;font-size:.88em}"
    "th{background:var(--surface);color:var(--fg-muted)}</style>"
    "</head><body><div class=\"wrap\"><h1>Software Bill of Materials (Linux)</h1>"
    f"<p style=\"color:var(--fg-muted);font-size:.82em\">Generated: {ts} &middot; {len(packages)} package(s)</p>"
    f"<table><thead><tr><th>Package Name</th><th>Version</th><th>Vendor</th></tr></thead><tbody>{pkg_rows}</tbody></table>"
    "</div></body></html>"
)
(report_dir / "index.html").write_text(html, encoding="utf-8")

print("")
print("=== SBOM Generation finished successfully ===")
sys.exit(0)
PY