"""Synthetic evaluation of the detector.

Two test sets are generated with fixed seeds:

1. ``baseline`` - the original 130-window set (100 sparse benign windows,
   10 brute-force, 10 request-flood, 10 endpoint-scan windows).
2. ``extended`` - adds harder benign cases (occasional failed logins,
   legitimately busy users) and further attack/suspicious scenarios
   (moderate repeated failed logins, HTTP error spikes, sensitive endpoint
   access) using a different seed.

Ground-truth labels are attached to each window here and are never passed to
the detector. These are synthetic windows built by this script: the results
show behaviour on these constructed patterns only and do not establish
real-world detection accuracy.
"""

import argparse
import json
import random
import uuid
from datetime import datetime, timezone, timedelta

from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

from src.config import MODEL_PATH
from src.detector import detect_threats, load_bundle, score_features
from src.features import SENSITIVE_PATHS, build_window_features

SEED = 42
random.seed(SEED)

USERS = [f"user{i}" for i in range(1, 101)]
NORMAL_ENDPOINTS = ["/home", "/products", "/search", "/about", "/contact"]
USER_AGENTS = ["Chrome/130", "Firefox/129", "Edge/130", "Safari/18"]
SCAN_PATHS = [
    "/admin", "/.env", "/backup", "/config", "/debug",
    "/phpmyadmin", "/server-status", "/wp-admin", "/actuator",
]


def make_event(ip, *, event_type="request", endpoint=None, status=200,
               user=None, country="India", user_agent=None, timestamp=None,
               response_bytes=None):
    timestamp = timestamp or datetime.now(timezone.utc)
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": timestamp.isoformat(),
        "source_ip": ip,
        "user_id": user or random.choice(USERS),
        "country": country,
        "city": "Synthetic",
        "event_type": event_type,
        "endpoint": endpoint or ("/login" if event_type == "login" else random.choice(NORMAL_ENDPOINTS)),
        "method": "POST" if event_type == "login" else "GET",
        "status_code": status,
        "response_bytes": response_bytes if response_bytes is not None else random.randint(100, 25000),
        "user_agent": user_agent or random.choice(USER_AGENTS),
    }


def make_window(ip, count, *, kind="normal", start=None):
    """Create one coherent IP window with event timestamps inside 5 minutes."""
    start = start or datetime.now(timezone.utc).replace(second=0, microsecond=0)
    events = []
    # Spread events evenly over (at most) the five-minute window.
    step = min(45.0, 290.0 / max(count, 1))

    def at(i):
        return start + timedelta(seconds=i * step)

    if kind in ("normal", "normal_high_traffic", "occasional_failed_logins"):
        # Training data assigns a stable user/IP profile. Do not generate
        # traffic from a fresh random user for each event: that is out of
        # distribution for the model and inflates false positives.
        normal_user = random.choice(USERS)
        normal_agent = random.choice(USER_AGENTS)
        failed_at = random.randrange(count) if kind == "occasional_failed_logins" else -1
        for i in range(count):
            if i == failed_at:
                events.append(make_event(
                    ip, event_type="login", endpoint="/api/login", status=401,
                    user=normal_user, user_agent=normal_agent, timestamp=at(i),
                    response_bytes=random.randint(100, 2500),
                ))
            elif random.random() < 0.20:
                events.append(make_event(
                    ip, event_type="login", endpoint="/api/login",
                    status=random.choices([200, 401], weights=[97, 3])[0],
                    user=normal_user, user_agent=normal_agent, timestamp=at(i),
                    response_bytes=random.randint(100, 2500),
                ))
            else:
                events.append(make_event(
                    ip, event_type="request",
                    endpoint=random.choice(["/", "/home", "/products", "/search",
                                            "/api/profile", "/api/orders"]),
                    status=random.choices(
                        [200, 302, 401, 403, 404, 500],
                        weights=[78, 8, 3, 2, 7, 2],
                    )[0],
                    user=normal_user, user_agent=normal_agent, timestamp=at(i),
                    response_bytes=random.randint(100, 8000),
                ))

    elif kind in ("brute_force", "repeated_failed_logins"):
        target = random.choice(USERS)
        for i in range(count):
            events.append(make_event(
                ip, event_type="login", endpoint="/login", status=401,
                user=target, user_agent="SyntheticAttackSimulator/1.0",
                timestamp=start + timedelta(seconds=i),
            ))

    elif kind == "request_flood":
        for i in range(count):
            events.append(make_event(
                ip, endpoint=random.choice(["/home", "/search", "/products"]),
                status=200, user_agent="SyntheticAttackSimulator/1.0",
                timestamp=start + timedelta(seconds=i),
            ))

    elif kind == "endpoint_scan":
        for i in range(count):
            events.append(make_event(
                ip, endpoint=SCAN_PATHS[i % len(SCAN_PATHS)], status=404,
                user_agent="SyntheticScanner/1.0",
                timestamp=start + timedelta(seconds=i),
            ))

    elif kind == "http_error_spike":
        user = random.choice(USERS)
        for i in range(count):
            events.append(make_event(
                ip, endpoint=random.choice(["/api/orders", "/api/profile", "/checkout"]),
                status=random.choice([500, 502, 503, 404]), user=user,
                user_agent="python-requests/2.32", timestamp=start + timedelta(seconds=2 * i),
            ))

    elif kind == "sensitive_access":
        paths = sorted(SENSITIVE_PATHS)
        user = random.choice(USERS)
        for i in range(count):
            events.append(make_event(
                ip, endpoint=paths[i % len(paths)], status=random.choice([200, 403]),
                user=user, user_agent="curl/8.5", timestamp=start + timedelta(seconds=3 * i),
            ))

    else:
        raise ValueError(kind)

    return events


# (kind, label, number of windows, event-count range)
BASELINE = [
    ("normal", 0, 100, (1, 3)),
    ("brute_force", 1, 10, (16, 22)),
    ("request_flood", 1, 10, (125, 145)),
    ("endpoint_scan", 1, 10, (12, 18)),
]
EXTENDED = [
    ("normal", 0, 100, (1, 3)),
    ("occasional_failed_logins", 0, 20, (4, 8)),
    ("normal_high_traffic", 0, 20, (25, 50)),
    ("brute_force", 1, 10, (16, 22)),
    ("repeated_failed_logins", 1, 10, (8, 12)),
    ("request_flood", 1, 10, (125, 145)),
    ("endpoint_scan", 1, 10, (12, 18)),
    ("http_error_spike", 1, 10, (15, 25)),
    ("sensitive_access", 1, 10, (6, 12)),
]


def build_set(spec, seed):
    random.seed(seed)
    base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
    samples, slot = [], 0
    for kind, label, n, (lo, hi) in spec:
        for i in range(n):
            ip = f"198.51.100.{i + 1}" if label == 0 else f"192.0.2.{10 + i}"
            events = make_window(ip, random.randint(lo, hi), kind=kind,
                                 start=base_time + timedelta(minutes=5 * slot))
            slot += 1
            samples.append((events, label, kind))
    return samples


def metrics(y_true, y_pred):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
        "precision": round(precision_score(y_true, y_pred, zero_division=0), 3),
        "recall": round(recall_score(y_true, y_pred, zero_division=0), 3),
        "f1": round(f1_score(y_true, y_pred, zero_division=0), 3),
        "fpr": round(fp / (fp + tn) if fp + tn else 0.0, 3),
    }


def evaluate(samples, bundle):
    y_true, ml, rules, combined, rows = [], [], [], [], {}
    for events, label, kind in samples:
        features = build_window_features(events, login_history=[])
        score = score_features(features, bundle)        # labels never reach the detector
        rule_hit = int(bool(detect_threats(features)))
        y_true.append(label)
        ml.append(score.prediction)
        rules.append(rule_hit)
        combined.append(int(score.prediction or rule_hit))
        r = rows.setdefault(kind, {"label": label, "n": 0, "ml": 0, "rules": 0, "combined": 0, "scores": []})
        r["n"] += 1
        r["ml"] += score.prediction
        r["rules"] += rule_hit
        r["combined"] += int(score.prediction or rule_hit)
        r["scores"].append(score.probability)
    return {
        "windows": len(samples),
        "ml_only": metrics(y_true, ml),
        "rules_only": metrics(y_true, rules),
        "ml_plus_rules": metrics(y_true, combined),
        "by_scenario": {
            k: {**{x: v[x] for x in ("label", "n", "ml", "rules", "combined")},
                "mean_score": round(sum(v["scores"]) / v["n"], 3)}
            for k, v in rows.items()
        },
    }


def print_report(name, result):
    print(f"\n##### {name} set: {result['windows']} windows #####")
    for key, title in (("ml_only", "Random Forest only (primary detector)"),
                       ("rules_only", "Supplementary rules only"),
                       ("ml_plus_rules", "Random Forest + rules (deployed alerting)")):
        m = result[key]
        print(f"\n=== {title} ===")
        print(f"TP={m['tp']} FP={m['fp']} FN={m['fn']} TN={m['tn']}")
        print(f"Precision: {m['precision']:.3f}")
        print(f"Recall:    {m['recall']:.3f}")
        print(f"F1-score:  {m['f1']:.3f}")
        print(f"FPR:       {m['fpr']:.3f}")
    print("\n=== Windows flagged per scenario (ML / rules / combined) ===")
    for kind, r in result["by_scenario"].items():
        what = "attack" if r["label"] else "benign"
        print(f"{kind:26s} [{what}] n={r['n']:3d}  ML={r['ml']:3d}  rules={r['rules']:3d}  "
              f"combined={r['combined']:3d}  mean RF score={r['mean_score']:.3f}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", help="also write the results to this JSON file")
    args = parser.parse_args()

    print(f"Loading model from: {MODEL_PATH}", flush=True)
    bundle = load_bundle()
    print(f"Model version: {bundle.version}")

    results = {
        "model_version": bundle.version,
        "baseline": evaluate(build_set(BASELINE, SEED), bundle),
        "extended": evaluate(build_set(EXTENDED, SEED + 1), bundle),
    }
    print_report("Baseline (original 130-window)", results["baseline"])
    print_report("Extended", results["extended"])
    print("\nSynthetic data only; these figures do not establish real-world accuracy.")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    main()
