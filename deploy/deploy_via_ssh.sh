#!/usr/bin/env bash
# Deploy the current working tree from your laptop (first deployment, or
# without GitHub Actions). Requires SSH access from admin_ip_cidr.
# Usage: VM_HOST=<public-ip> [VM_USER=azureuser] ./deploy/deploy_via_ssh.sh
set -euo pipefail
: "${VM_HOST:?set VM_HOST to the VM public IP (terraform output vm_public_ip)}"
VM_USER=${VM_USER:-azureuser}
cd "$(dirname "$0")/.."

REV=$(git rev-parse --short=12 HEAD 2>/dev/null || echo nogit)
ID="${REV}-$(date -u +%Y%m%d%H%M%S)-ssh"
TARBALL=$(mktemp -t seclog-release).tar.gz

# Ship only source: no venv, data, secrets or Terraform state.
# (COPYFILE_DISABLE/--no-xattrs keep macOS metadata out of the archive.)
COPYFILE_DISABLE=1 tar --no-xattrs -czf "$TARBALL" \
  --exclude=.venv --exclude=.git --exclude=data --exclude=.env \
  --exclude='__pycache__' --exclude=.pytest_cache --exclude='infra/terraform/.terraform' \
  --exclude='*.tfstate*' --exclude='infra/terraform/terraform.tfvars' \
  --exclude='models/random_forest_model.joblib' .

scp "$TARBALL" "$VM_USER@$VM_HOST:/tmp/seclog-release.tar.gz"
# $ID and $REV are expanded locally on purpose.
# shellcheck disable=SC2087
ssh "$VM_USER@$VM_HOST" "sudo bash -s" <<REMOTE
set -euo pipefail
mkdir -p /opt/seclog/releases/$ID
tar -xzf /tmp/seclog-release.tar.gz -C /opt/seclog/releases/$ID
rm -f /tmp/seclog-release.tar.gz
echo "$REV" > /opt/seclog/releases/$ID/REVISION
bash /opt/seclog/releases/$ID/deploy/install_release.sh /opt/seclog/releases/$ID $ID
REMOTE
rm -f "$TARBALL"
