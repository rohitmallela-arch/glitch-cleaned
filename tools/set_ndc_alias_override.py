"""Usage:
python tools/set_ndc_alias_override.py --ndc 12345678901 --name "Metformin 500mg"
python tools/set_ndc_alias_override.py --csv /path/to/overrides.csv
"""

import argparse
import csv
import datetime
import sys
from typing import Iterable, Tuple

from google.cloud import firestore


def _ndc_digits(raw: str) -> str:
    return "".join(ch for ch in (raw or "").strip() if ch.isdigit())


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _upsert_override(db: firestore.Client, ndc_digits: str, display_name: str) -> None:
    db.collection("ndc_alias_overrides").document(ndc_digits).set(
        {
            "ndc_digits": ndc_digits,
            "display_name": display_name,
            "source": "manual",
            "updated_at": _utc_now_iso(),
        },
        merge=True,
    )


def _iter_csv_rows(path: str) -> Iterable[Tuple[int, str, str]]:
    with open(path, "r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for i, row in enumerate(reader, start=2):
            yield i, (row.get("ndc_digits") or ""), (row.get("display_name") or "")


def main() -> int:
    parser = argparse.ArgumentParser(description="Upsert manual NDC display-name overrides.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ndc", help="NDC digits (digits-only)")
    group.add_argument("--csv", help="Path to CSV with headers: ndc_digits,display_name")
    parser.add_argument("--name", help="Display name for single override")
    args = parser.parse_args()

    rows = []
    if args.ndc:
        if not args.name:
            print("error: --name is required when using --ndc", file=sys.stderr)
            return 2
        rows.append((1, args.ndc, args.name))
    else:
        rows.extend(_iter_csv_rows(args.csv))

    db = firestore.Client()
    ok_count = 0
    fail_count = 0

    for row_num, ndc_raw, name_raw in rows:
        ndc_digits = _ndc_digits(ndc_raw)
        display_name = (name_raw or "").strip()
        if not ndc_digits:
            fail_count += 1
            print(f"row {row_num}: invalid ndc_digits", file=sys.stderr)
            continue
        if not display_name:
            fail_count += 1
            print(f"row {row_num}: missing display_name", file=sys.stderr)
            continue
        try:
            _upsert_override(db, ndc_digits, display_name)
            ok_count += 1
        except Exception as exc:
            fail_count += 1
            print(f"row {row_num}: upsert failed ({exc})", file=sys.stderr)

    total_rows = ok_count + fail_count
    print(f"total_rows={total_rows} ok_count={ok_count} fail_count={fail_count}")
    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
