
import csv
from pathlib import Path
import pandas as pd

path = Path("data/alerts.csv")
backup = Path("data/alerts_backup.csv")

if not path.exists():
    print("alerts.csv not found.")
    raise SystemExit(1)

# Preserve the original before attempting repair.
backup.write_bytes(path.read_bytes())
print(f"Backup saved to: {backup}")

# Read rows without requiring every row to have the same width.
with path.open("r", encoding="utf-8-sig", newline="") as f:
    rows = list(csv.reader(f))

if not rows:
    print("The file is empty.")
    raise SystemExit(0)

header = rows[0]
width = len(header)
repaired = []
skipped = 0

for line_number, row in enumerate(rows[1:], start=2):
    if len(row) == width:
        repaired.append(row)
    elif len(row) > width:
        # Only repair extra fields when the extra data is in the
        # reason column. Other malformed rows are skipped.
        reason_index = header.index("reason") if "reason" in header else -1

        if reason_index >= 0 and len(row) == width + 1:
            fixed = row[:]
            fixed[reason_index] = (
                fixed[reason_index] + "; " + fixed[reason_index + 1]
            )
            del fixed[reason_index + 1]
            repaired.append(fixed)
            print(f"Merged extra field on line {line_number}.")
        else:
            skipped += 1
            print(f"Skipped malformed line {line_number}: {len(row)} fields.")
    else:
        skipped += 1
        print(f"Skipped incomplete line {line_number}: {len(row)} fields.")

# Write a consistent CSV.
temp = path.with_name("alerts_repaired.csv")
with temp.open("w", encoding="utf-8", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(header)
    writer.writerows(repaired)

# Verify the repaired file before replacing the original.
check = pd.read_csv(temp)

temp.replace(path)

print(f"\nRepair complete. Valid records: {len(check)}")
print(f"Skipped rows: {skipped}")
print(f"Columns: {check.columns.tolist()}")

if "priority" in check.columns:
    print("\nSeverity counts:")
    print(check["priority"].value_counts(dropna=False))

if "threat_types" in check.columns:
    print("\nRows with threat types:", check["threat_types"].notna().sum())