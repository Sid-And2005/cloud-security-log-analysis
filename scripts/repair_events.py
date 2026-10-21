
import csv
from pathlib import Path
import pandas as pd

path = Path("data/events.csv")
backup = Path("data/events_backup.csv")
temp = Path("data/events_repaired.csv")

if not path.exists():
    raise SystemExit("data/events.csv not found.")

# Back up the original file before changing anything.
backup.write_bytes(path.read_bytes())
print(f"Backup saved to {backup}")

with path.open("r", encoding="utf-8-sig", newline="") as f:
    rows = list(csv.reader(f))

if not rows:
    raise SystemExit("events.csv is empty.")

header = rows[0]
expected = len(header)
repaired = []
skipped = 0

for line_number, row in enumerate(rows[1:], start=2):
    if len(row) == expected:
        repaired.append(row)

    elif len(row) == expected + 1:
        # The newer detector added threat_types.
        # Preserve the extra value by appending it to the existing reason.
        fixed = row[:]
        if "reason" in header:
            reason_index = header.index("reason")
            fixed[reason_index] = (
                fixed[reason_index] + "; " + fixed[-1]
            )
        fixed = fixed[:expected]
        repaired.append(fixed)
        print(f"Repaired line {line_number}")

    else:
        skipped += 1
        print(
            f"Skipped line {line_number}: "
            f"expected {expected} fields, got {len(row)}"
        )

with temp.open("w", encoding="utf-8", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(header)
    writer.writerows(repaired)

# Verify the new file parses before replacing the original.
verified = pd.read_csv(temp)
temp.replace(path)

print(f"\nRepair complete: {len(verified)} records preserved.")
print(f"Skipped malformed rows: {skipped}")
print(f"Columns: {verified.columns.tolist()}")