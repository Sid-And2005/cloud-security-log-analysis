"""Operational commands.

    python manage.py init-db        create/upgrade the PostgreSQL schema
    python manage.py health         check config, model, storage, archive, consumer
    python manage.py check-model    validate the model bundle and feature schema
    python manage.py init-archive   create the blob container (local Azurite only;
                                    Terraform creates it in Azure)
"""

import argparse
import json
import sys
from datetime import datetime, timezone

from src import config


def consumer_heartbeat():
    path = config.HEARTBEAT_FILE
    if not path.exists():
        return {"ok": False, "detail": "no heartbeat file (consumer never ran)"}
    try:
        beat = json.loads(path.read_text(encoding="utf-8"))
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(beat["ts"])).total_seconds()
    except (ValueError, KeyError) as exc:
        return {"ok": False, "detail": f"unreadable heartbeat: {exc}"}
    ok = age <= config.HEARTBEAT_MAX_AGE_SECONDS and beat.get("status") == "running"
    return {"ok": ok, "age_seconds": round(age, 1), **beat}


def cmd_init_db(_args):
    from src.storage import get_storage

    config.validate_settings()
    storage = get_storage()
    if hasattr(storage, "ensure_database") and storage.ensure_database():
        print(f"Created database {config.PGDATABASE}")
    applied = storage.init_schema()
    print(f"Schema ready on {storage.name}; newly applied: {applied or 'none'}")
    storage.close()


def cmd_init_archive(_args):
    from azure.core.exceptions import ResourceExistsError

    from src.cloud.blob_storage import BlobArchiver

    config.validate_settings()
    try:
        BlobArchiver().container.create_container()
        print(f"Created container {config.AZURE_STORAGE_CONTAINER}")
    except ResourceExistsError:
        print(f"Container {config.AZURE_STORAGE_CONTAINER} already exists")


def cmd_check_model(_args):
    from src.detector import load_bundle

    bundle = load_bundle()
    print(f"OK: {bundle.path}")
    print(f"  version:        {bundle.version}")
    print(f"  features:       {len(bundle.feature_columns)} (match src/features.py)")
    print(f"  classes:        {list(bundle.model.classes_)} (anomaly index {bundle.anomaly_index})")


def cmd_health(args):
    from src.cloud.blob_storage import get_archiver
    from src.detector import ModelError, load_bundle
    from src.storage import get_storage

    report = {"config": {"ok": True, **config.describe()}}
    try:
        config.validate_settings()
    except config.ConfigError as exc:
        report["config"] = {"ok": False, "detail": str(exc)}

    try:
        report["model"] = {"ok": True, "version": load_bundle().version}
    except ModelError as exc:
        report["model"] = {"ok": not config.REQUIRE_MODEL, "detail": str(exc)}

    report["storage"] = get_storage().health()
    report["archive"] = get_archiver().health()
    if not args.skip_consumer:
        report["consumer"] = consumer_heartbeat()

    healthy = all(part.get("ok") for part in report.values())
    print(json.dumps({"healthy": healthy, **report}, indent=2, default=str))
    get_storage().close()
    return 0 if healthy else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init-db").set_defaults(func=cmd_init_db)
    sub.add_parser("check-model").set_defaults(func=cmd_check_model)
    sub.add_parser("init-archive").set_defaults(func=cmd_init_archive)
    health = sub.add_parser("health")
    health.add_argument("--skip-consumer", action="store_true", help="do not require a live consumer heartbeat")
    health.set_defaults(func=cmd_health)

    args = parser.parse_args()
    sys.exit(args.func(args) or 0)


if __name__ == "__main__":
    main()
