#!/usr/bin/env bash
# Install an extracted release on the VM, switch to it, and verify it.
# Runs as root. Usage: install_release.sh <extracted-release-dir> <release-id>
#
#   /opt/seclog/releases/<id>/   code + its own virtualenv
#   /opt/seclog/current -> releases/<id>   (atomic symlink switch)
#
# If the health check fails, the previous release is restored and the script
# exits non-zero, so a deployment is never reported successful unverified.
set -euo pipefail

SRC=${1:?usage: install_release.sh <release-dir> <release-id>}
ID=${2:?usage: install_release.sh <release-dir> <release-id>}
APP_ROOT=/opt/seclog
REL="$APP_ROOT/releases/$ID"
ENV_FILE=/etc/seclog/seclog.env
SERVICES=(seclog-consumer seclog-dashboard)
KEEP_RELEASES=3

log() { echo "[deploy $(date -u +%H:%M:%S)] $*"; }

# Run a command as the app user with exactly the services' environment.
run_as_app() {
  systemd-run --quiet --wait --pipe --collect \
    --uid=seclog --gid=seclog \
    --property=EnvironmentFile="$ENV_FILE" \
    --setenv=SERVICE_NAME=deploy \
    --working-directory="$1" "${@:2}"
}

[[ -f "$ENV_FILE" ]] || { echo "$ENV_FILE missing (was the VM provisioned by Terraform?)"; exit 1; }

if [[ "$(readlink -f "$SRC")" != "$(readlink -f "$REL" 2>/dev/null || true)" ]]; then
  rm -rf "$REL"
  mkdir -p "$APP_ROOT/releases"
  cp -a "$SRC" "$REL"
fi

log "Creating virtualenv for release $ID"
python3 -m venv "$REL/.venv"
"$REL/.venv/bin/pip" install --quiet --upgrade pip
"$REL/.venv/bin/pip" install --quiet -r "$REL/requirements.txt"
chown -R root:seclog "$REL"
chmod -R u=rwX,g=rX,o= "$REL"

log "Validating model bundle and database schema"
run_as_app "$REL" "$REL/.venv/bin/python" manage.py check-model
run_as_app "$REL" "$REL/.venv/bin/python" manage.py init-db

PREVIOUS=$(readlink -f "$APP_ROOT/current" 2>/dev/null || true)

install -m 0644 "$REL"/deploy/systemd/*.service /etc/systemd/system/
install -m 0755 "$REL"/deploy/seclog /usr/local/bin/seclog
systemctl daemon-reload

switch_to() {
  ln -sfn "$1" "$APP_ROOT/current.new"
  mv -T "$APP_ROOT/current.new" "$APP_ROOT/current"
  systemctl enable --quiet "${SERVICES[@]}"
  # A crash-looping release can hit StartLimitBurst; clear it so restart works.
  systemctl reset-failed "${SERVICES[@]}" 2>/dev/null || true
  systemctl restart "${SERVICES[@]}"
}

healthy() {
  for _ in $(seq 1 30); do
    sleep 3
    if systemctl is-active --quiet "${SERVICES[@]}" \
      && curl -fsS --max-time 3 http://127.0.0.1:8501/_stcore/health >/dev/null \
      && run_as_app "$APP_ROOT/current" "$APP_ROOT/current/.venv/bin/python" manage.py health >/tmp/seclog-health.json 2>&1; then
      return 0
    fi
  done
  return 1
}

log "Switching to release $ID"
switch_to "$REL"

if healthy; then
  cat /tmp/seclog-health.json
  log "Health check passed"
  # Keep the newest releases only (never the active one).
  # shellcheck disable=SC2012  # release names are <hex>-<digits>
  ls -1dt "$APP_ROOT"/releases/*/ | tail -n +$((KEEP_RELEASES + 1)) | while read -r old; do
    [[ "$(readlink -f "$old")" == "$(readlink -f "$APP_ROOT/current")" ]] || rm -rf "$old"
  done
  echo "DEPLOY_RESULT=SUCCESS release=$ID"
  exit 0
fi

log "Health check FAILED for release $ID"
cat /tmp/seclog-health.json 2>/dev/null || true
journalctl -u seclog-consumer -u seclog-dashboard -n 40 --no-pager || true
if [[ -n "$PREVIOUS" && -d "$PREVIOUS" && "$PREVIOUS" != "$(readlink -f "$REL")" ]]; then
  log "Rolling back to $PREVIOUS"
  switch_to "$PREVIOUS"
  # Remove the failed release so a later manual rollback cannot pick it.
  rm -rf "$REL"
  echo "DEPLOY_RESULT=ROLLED_BACK release=$ID previous=$(basename "$PREVIOUS")"
else
  echo "DEPLOY_RESULT=FAILED release=$ID (no previous release to roll back to)"
fi
exit 1
