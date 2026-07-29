#!/usr/bin/env python3
"""Refresh the upstream lookup-table sources into assets/.

Downloads the IEEE MAC address registries and the Bluetooth SIG assigned-number
YAMLs that build.rs compiles into the OUI / company / UUID / appearance tables.

The IEEE side is four registries covering four assignment sizes: MA-L (24-bit
OUI), MA-M (28-bit), MA-S (36-bit), and IAB (36-bit). IAB is a closed registry —
IEEE folded it into MA-S and issues no new blocks — and is kept because devices
holding an IAB assignment are still in the field.
After a refresh, rebuild the firmware (`cargo build --release`) and re-provision
the external flash (`scripts/provision.sh`) to pick up the new data.

Run it with the project virtualenv, which has `requests` installed:
    .venv/bin/python scripts/refresh_data.py [name ...]

With no arguments, refreshes everything. Otherwise only the named files (keys
below), e.g. `.venv/bin/python scripts/refresh_data.py oui`.
"""

import sys
import tempfile
from pathlib import Path

try:
    import requests
except ModuleNotFoundError:
    sys.exit(
        "requests not found — run with the project venv:\n"
        "    .venv/bin/python scripts/refresh_data.py"
    )

# Bluetooth SIG public assigned-numbers repo (Bitbucket), pinned to HEAD.
SIG = "https://bitbucket.org/bluetooth-SIG/public/raw/HEAD/assigned_numbers"

# Destination filename -> source URL.
SOURCES = {
    "oui.csv": "https://standards-oui.ieee.org/oui/oui.csv",
    "mam.csv": "https://standards-oui.ieee.org/oui28/mam.csv",
    "oui36.csv": "https://standards-oui.ieee.org/oui36/oui36.csv",
    "iab.csv": "https://standards-oui.ieee.org/iab/iab.csv",
    "company_identifiers.yaml": f"{SIG}/company_identifiers/company_identifiers.yaml",
    "service_uuids.yaml": f"{SIG}/uuids/service_uuids.yaml",
    "member_uuids.yaml": f"{SIG}/uuids/member_uuids.yaml",
    "sdo_uuids.yaml": f"{SIG}/uuids/sdo_uuids.yaml",
    "characteristic_uuids.yaml": f"{SIG}/uuids/characteristic_uuids.yaml",
    "descriptors.yaml": f"{SIG}/uuids/descriptors.yaml",
    "declarations.yaml": f"{SIG}/uuids/declarations.yaml",
    "appearance_values.yaml": f"{SIG}/core/appearance_values.yaml",
    "ad_types.yaml": f"{SIG}/core/ad_types.yaml",
    "uri_schemes.yaml": f"{SIG}/core/uri_schemes.yaml",
}

ASSETS = Path(__file__).resolve().parent.parent / "assets"

# A browser-like UA; the IEEE server rejects the default urllib agent.
UA = "Mozilla/5.0 (refresh_data.py; sonde)"


def download(name: str, url: str) -> None:
    dest = ASSETS / name
    print(f"↓ {name}\n  {url}")
    resp = requests.get(url, headers={"User-Agent": UA}, timeout=120)
    resp.raise_for_status()
    data = resp.content
    if not data:
        raise RuntimeError("empty response")
    # Write to a temp file in the same dir, then atomically replace.
    with tempfile.NamedTemporaryFile(dir=ASSETS, delete=False) as tmp:
        tmp.write(data)
        tmp_path = Path(tmp.name)
    tmp_path.replace(dest)
    print(f"  {len(data):,} bytes -> {dest.relative_to(ASSETS.parent)}")


def main() -> int:
    wanted = sys.argv[1:]
    if wanted:
        unknown = [w for w in wanted if w not in SOURCES]
        if unknown:
            print(f"unknown source(s): {', '.join(unknown)}", file=sys.stderr)
            print(f"available: {', '.join(SOURCES)}", file=sys.stderr)
            return 2
        names = wanted
    else:
        names = list(SOURCES)

    ASSETS.mkdir(parents=True, exist_ok=True)
    failed = []
    for name in names:
        try:
            download(name, SOURCES[name])
        except Exception as e:  # noqa: BLE001 - report and continue
            print(f"  FAILED: {e}", file=sys.stderr)
            failed.append(name)

    if failed:
        print(f"\n{len(failed)} failed: {', '.join(failed)}", file=sys.stderr)
        return 1
    print("\ndone — rebuild + reprovision to apply.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
