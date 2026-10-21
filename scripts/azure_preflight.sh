#!/usr/bin/env bash
# Read-only checks before `terraform apply` (creates nothing, costs nothing,
# except registering resource providers, which is free).
# Run after `az login`:   ./scripts/azure_preflight.sh [region] [vm_size] [pg_sku]
set -euo pipefail

REGION=${1:-eastasia}
VM_SIZE=${2:-Standard_B2als_v2}
PG_SKU=${3:-Standard_B1ms}
PROVIDERS=(Microsoft.Compute Microsoft.Network Microsoft.Storage Microsoft.DBforPostgreSQL
  Microsoft.OperationalInsights Microsoft.Insights Microsoft.ManagedIdentity)

ok() { echo "  [OK]   $*"; }
bad() { echo "  [FAIL] $*"; FAILED=1; }
FAILED=0

echo "== Account"
az account show --query '{subscription:name, id:id, state:state, user:user.name}' -o table \
  || { echo "Not logged in: run 'az login' first"; exit 1; }
STATE=$(az account show --query state -o tsv)
if [[ "$STATE" == "Enabled" ]]; then ok "subscription enabled"; else bad "subscription state is $STATE"; fi

echo "== Role (needs Owner, or Contributor + User Access Administrator, for role assignments)"
ME=$(az ad signed-in-user show --query id -o tsv 2>/dev/null || true)
if [[ -n "$ME" ]]; then
  ROLES=$(az role assignment list --assignee "$ME" --all --query '[].roleDefinitionName' -o tsv | sort -u | tr '\n' ' ')
  echo "  roles: ${ROLES:-none found}"
  if [[ "$ROLES" == *Owner* || "$ROLES" == *"User Access Administrator"* ]]; then
    ok "can create role assignments"
  else
    bad "cannot create role assignments (managed identity access would fail)"
  fi
fi

echo "== Region policy (universities often restrict student subscriptions)"
ALLOWED=$(az policy assignment list \
  --query "[].parameters.listOfAllowedLocations.value[]" -o tsv 2>/dev/null | sort -u | tr '\n' ' ')
if [[ -z "$ALLOWED" ]]; then
  ok "no allowed-locations policy found"
elif [[ " $ALLOWED " == *" $REGION "* ]]; then
  ok "$REGION is allowed (allowed: $ALLOWED)"
else
  bad "$REGION is blocked by policy; allowed regions: $ALLOWED"
fi

echo "== Resource providers (registering is free)"
for p in "${PROVIDERS[@]}"; do
  s=$(az provider show -n "$p" --query registrationState -o tsv 2>/dev/null || echo NotRegistered)
  if [[ "$s" != "Registered" ]]; then
    az provider register -n "$p" >/dev/null && echo "  [..]   $p: registering (takes a few minutes)"
  else
    ok "$p"
  fi
done

echo "== VM size $VM_SIZE in $REGION"
RESTRICT=$(az vm list-skus -l "$REGION" --size "$VM_SIZE" --resource-type virtualMachines \
  --query "[?name=='$VM_SIZE'].restrictions[].reasonCode" -o tsv 2>/dev/null || echo ERR)
FOUND=$(az vm list-skus -l "$REGION" --size "$VM_SIZE" --resource-type virtualMachines \
  --query "length([?name=='$VM_SIZE'])" -o tsv 2>/dev/null || echo 0)
if [[ "$FOUND" == "0" ]]; then bad "$VM_SIZE not offered in $REGION"
elif [[ -n "$RESTRICT" ]]; then bad "$VM_SIZE restricted in $REGION: $RESTRICT"
else ok "$VM_SIZE available"; fi

echo "== vCPU quota in $REGION (the VM needs 2)"
az vm list-usage -l "$REGION" --query "[?name.value=='cores' || name.value=='standardBSFamily'].{quota:name.localizedValue, used:currentValue, limit:limit}" -o table || true

echo "== PostgreSQL Flexible Server $PG_SKU in $REGION"
if az postgres flexible-server list-skus -l "$REGION" -o json 2>/dev/null \
    | grep -q "\"$PG_SKU\""; then ok "$PG_SKU available"
else bad "$PG_SKU not available in $REGION (or the region blocks PostgreSQL for this subscription)"; fi

echo
if [[ $FAILED == 0 ]]; then
  echo "All checks passed for $REGION. Next: cd infra/terraform && terraform plan -out tfplan"
else
  echo "Some checks failed. Try another region, e.g.: $0 eastasia"
  exit 1
fi
