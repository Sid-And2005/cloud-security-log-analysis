#!/usr/bin/env bash
# Entry point for Azure Run Command (invoked by .github/workflows/deploy.yml).
# Downloads the exact commit from GitHub using the workflow's short-lived
# GITHUB_TOKEN (passed as a protected parameter, never logged) and installs it.
# Parameters (environment variables): REPO=owner/name SHA=<commit> GITHUB_TOKEN=<token>
set -euo pipefail
: "${REPO:?}" "${SHA:?}" "${GITHUB_TOKEN:?}"
[[ "$SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "SHA must be a full commit hash"; exit 1; }

ID="${SHA:0:12}-$(date -u +%Y%m%d%H%M%S)"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

curl -fsSL --retry 3 \
  -H "Authorization: Bearer ${GITHUB_TOKEN}" \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/${REPO}/tarball/${SHA}" -o "$WORK/release.tar.gz"
unset GITHUB_TOKEN

mkdir -p /opt/seclog/releases/"$ID"
tar -xzf "$WORK/release.tar.gz" --strip-components=1 -C /opt/seclog/releases/"$ID"
echo "$SHA" > /opt/seclog/releases/"$ID"/REVISION
exec bash /opt/seclog/releases/"$ID"/deploy/install_release.sh /opt/seclog/releases/"$ID" "$ID"
