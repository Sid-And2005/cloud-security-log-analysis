
import argparse
import json
import random
import time
import uuid
from datetime import datetime, timezone

from src.config import INCOMING_DIR

USERS = [f"user{i}" for i in range(1, 101)]

NORMAL_IPS = (
    [f"198.51.100.{i}" for i in range(1, 200)]
    + [f"203.0.113.{i}" for i in range(1, 100)]
)

ATTACK_IPS = [
    "192.0.2.10",
    "192.0.2.11",
    "192.0.2.12",
    "192.0.2.13",
    "192.0.2.14",
]

TARGET_USERS = ["user3", "user12", "user25", "user48", "user76"]

NORMAL_ENDPOINTS = ["/home", "/products", "/search", "/about", "/contact"]
SCAN_ENDPOINTS = [
    "/admin", "/.env", "/backup", "/config", "/debug",
    "/phpmyadmin", "/server-status", "/wp-admin", "/actuator",
]

USER_AGENTS = [
    "Chrome/130", "Firefox/129", "Edge/130", "Safari/18"
]


def make_event(
    source_ip=None,
    user_id=None,
    event_type=None,
    endpoint=None,
    status_code=None,
    country="India",
    user_agent=None,
):
    event_type = event_type or random.choice(["request", "login"])
    endpoint = endpoint or (
        random.choice(NORMAL_ENDPOINTS)
        if event_type == "request"
        else "/login"
    )

    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": source_ip or random.choice(NORMAL_IPS),
        "user_id": user_id or random.choice(USERS),
        "country": country,
        "city": "Synthetic",
        "event_type": event_type,
        "endpoint": endpoint,
        "method": "POST" if event_type == "login" else "GET",
        "status_code": (
            status_code if status_code is not None
            else random.choices(
                [200, 201, 401, 404, 500],
                weights=[82, 5, 3, 8, 2],
            )[0]
        ),
        "response_bytes": random.randint(100, 25000),
        "user_agent": user_agent or random.choice(USER_AGENTS),
    }


def make_normal_event():
    # Keep a stable user and user-agent per normal source IP, matching the
    # profile structure in generate_logs.py and avoiding artificial
    # unique-user spikes within a single IP's five-minute window.
    source_ip = random.choice(NORMAL_IPS)
    profile_index = NORMAL_IPS.index(source_ip)
    user_id = USERS[profile_index % len(USERS)]
    user_agent = USER_AGENTS[profile_index % len(USER_AGENTS)]

    if random.random() < 0.20:
        return make_event(
            source_ip=source_ip,
            user_id=user_id,
            user_agent=user_agent,
            event_type="login",
            endpoint="/api/login",
            status_code=random.choices(
                [200, 401], weights=[97, 3]
            )[0],
        )
    return make_event(
        source_ip=source_ip,
        user_id=user_id,
        user_agent=user_agent,
        event_type="request",
        endpoint=random.choice(["/", "/home", "/products", "/search",
                                "/api/profile", "/api/orders", "/api/logout"]),
        status_code=random.choices(
            [200, 302, 401, 403, 404, 500],
            weights=[78, 8, 3, 2, 7, 2],
        )[0],
    )


def make_attack_burst():
    """Return a coherent burst of events from one recurring source IP."""
    kind = random.choice(["brute_force", "request_flood", "endpoint_scan"])
    ip = random.choice(ATTACK_IPS)
    events = []

    if kind == "brute_force":
        user = random.choice(TARGET_USERS)
        for _ in range(random.randint(16, 22)):
            events.append(make_event(
                source_ip=ip,
                user_id=user,
                event_type="login",
                endpoint="/login",
                status_code=401,
                user_agent="SyntheticAttackSimulator/1.0",
            ))

    elif kind == "request_flood":
        for _ in range(random.randint(125, 145)):
            events.append(make_event(
                source_ip=ip,
                user_id=random.choice(USERS),
                event_type="request",
                endpoint=random.choice(["/search", "/products", "/home"]),
                status_code=200,
                user_agent="SyntheticAttackSimulator/1.0",
            ))

    else:
        for _ in range(random.randint(12, 18)):
            events.append(make_event(
                source_ip=ip,
                user_id=random.choice(TARGET_USERS),
                event_type="request",
                endpoint=random.choice(SCAN_ENDPOINTS),
                status_code=random.choice([403, 404]),
                user_agent="SyntheticScanner/1.0",
            ))

    return kind, events


def write_event(event):
    INCOMING_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.fromisoformat(
        event["timestamp"].replace("Z", "+00:00")
    )
    filename = f"{timestamp.strftime('%Y%m%dT%H%M%S%fZ')}_{event['event_id']}.json"

    destination = INCOMING_DIR / filename
    temporary = INCOMING_DIR / f".{filename}.tmp"

    with temporary.open("w", encoding="utf-8") as f:
        json.dump(event, f, ensure_ascii=False)
        f.flush()

    temporary.replace(destination)


def main():
    parser = argparse.ArgumentParser(
        description="Synthetic security log producer"
    )
    parser.add_argument("--interval", type=float, default=0.5)
    parser.add_argument(
        "--burst-interval",
        type=float,
        default=15.0,
        help="Seconds between simulated attack campaigns",
    )
    parser.add_argument(
        "--burst-delay",
        type=float,
        default=0.03,
        help="Delay between events within an attack campaign",
    )
    args = parser.parse_args()

    if args.interval <= 0 or args.burst_interval <= 0 or args.burst_delay < 0:
        parser.error("Intervals must be positive; burst delay cannot be negative")

    INCOMING_DIR.mkdir(parents=True, exist_ok=True)
    next_burst = time.monotonic() + args.burst_interval

    print(f"Writing events to: {INCOMING_DIR.resolve()}")
    print("Normal traffic is mixed with recurring attack campaigns.")
    print("Press Ctrl+C to stop.")

    try:
        while True:
            if time.monotonic() >= next_burst:
                kind, burst = make_attack_burst()
                print(f"\n[SIMULATED CAMPAIGN] {kind}: {len(burst)} events")

                for event in burst:
                    write_event(event)
                    print(
                        f"  {event['source_ip']} | {event['endpoint']} | "
                        f"HTTP {event['status_code']}",
                        flush=True,
                    )
                    if args.burst_delay:
                        time.sleep(args.burst_delay)

                next_burst = time.monotonic() + args.burst_interval
            else:
                event = make_normal_event()

                # Attack traffic is generated only by make_attack_burst(),
                # so normal events remain genuinely normal for evaluation.

                write_event(event)
                print(
                    f"{event['source_ip']} | {event['user_id']} | "
                    f"{event['endpoint']} | HTTP {event['status_code']}",
                    flush=True,
                )
                time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\nProducer stopped.")


if __name__ == "__main__":
    main()