"""Verify the ATT&CK catalogue against attack-stix-data bundles.

    python -m backend.app.tools.verify_attack enterprise-attack.json ics-attack.json

Bundles come from https://github.com/mitre-attack/attack-stix-data. Exits 1 if
any catalogued technique is missing, renamed, revoked or deprecated.
"""

import argparse
import json
import sys

from ..services.detection.attack import verify_against_stix


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundles", nargs="+")
    report = verify_against_stix(parser.parse_args().bundles)
    print(json.dumps(report, indent=2))
    sys.exit(1 if report["missing"] or report["renamed"] or report["deprecated"] else 0)


if __name__ == "__main__":
    main()
