require_quorum() {
    echo "Approval required from two administrators."

    read -rp "Admin1 token: " token1
    read -rp "Admin2 token: " token2

    if [[ "$token1" != "$ADMIN1_TOKEN" ]] || [[ "$token2" != "$ADMIN2_TOKEN" ]]; then
        log "Quorum validation failed."
        exit 1
    fi

    log "Quorum validated."
}
validate_execution_window() {
    NOW=$(date +%s)
    if (( NOW > EXECUTION_EXPIRY )); then
        log "Execution window expired."
        exit 1
    fi
}
az lock create --name snapshot-lock \
  --lock-type CanNotDelete \
  --resource-group myrg
aws s3api put-object-lock-configuration \
  --bucket my-bucket \
  --object-lock-configuration ObjectLockEnabled=Enabled
az network public-ip list --query "[].{name:name,rg:resourceGroup}" -o tsv \
| while read name rg; do
    az network public-ip delete -g "$rg" -n "$name"
  done
aws autoscaling update-auto-scaling-group \
  --auto-scaling-group-name my-asg \
  --min-size 0 --max-size 0 --desired-capacity 0
notify() {
    curl -X POST -H 'Content-type: application/json' \
    --data "{\"text\":\"Containment mode activated at $(date)\"}" \
    $SLACK_WEBHOOK_URL
}
az group export --name myrg > recovery_template.json
aws cloudformation list-stacks > recovery_stacks.json
if [[ "$1" == "--recover" ]]; then
    log "Initiating recovery sequence."
    # reattach IGWs
    # restore NSGs
    # scale services back
    exit 0
fi
ADMIN1_TOKEN=$(az keyvault secret show --vault-name myvault --name admin1 --query value -o tsv)
aws cloudtrail create-trail \
  --name OrgTrail \
  --s3-bucket-name my-audit-bucket \
  --is-multi-region-trail
aws cloudtrail start-logging --name OrgTrail
az monitor diagnostic-settings create \
  --name ActivityLogExport \
  --resource "/subscriptions/<sub-id>" \
  --logs '[{"category": "Administrative","enabled": true}]' \
  --workspace <log-analytics-workspace-id>
    aws configservice put-configuration-recorder \
  --configuration-recorder name=default,roleARN=arn:aws:iam::<acct>:role/aws-config-role
az policy assignment create \
  --name enforce-tags \
  --policy <policy-id> \
  --scope /subscriptions/<sub-id>
    aws ec2 detach-internet-gateway \
  --internet-gateway-id igw-xxxx \
  --vpc-id vpc-xxxx
az network nsg rule create \
  --resource-group myrg \
  --nsg-name myNSG \
  --name DenyAllInbound \
  --priority 4096 \
  --direction Inbound \
  --access Deny \
  --protocol '*'
if [[ "$APPROVAL_COUNT" -lt 2 ]]; then
    echo "Insufficient approvals."
    exit 1
fi
aws ec2 create-snapshot \
  --volume-id vol-xxxx \
  --description "Pre-change backup"
az group export --name myrg > recovery_template.json
AWS CloudFormation
aws cloudformation list-stacks > stack_export.json
aws iam create-access-key --user-name myuser
az ad conditional-access policy create ...
  1. Audit
2. Snapshot
3. Log
4. Approve
5. Apply change
6. Verify
7. Alert
8. Rollback if needed
diff --git a/emergency_shutdown_orchestrator.sh b/emergency_shutdown_orchestrator.sh
new file mode 100755
index 0000000000000000000000000000000000000000..d88ac11135303743c28540a05614aae829d68130
--- /dev/null
+++ b/emergency_shutdown_orchestrator.sh
@@ -0,0 +1,302 @@
+#!/usr/bin/env bash
+
+# ======================================================
+# EPHEMERAL MULTI-CLOUD EMERGENCY SHUTDOWN ORCHESTRATOR
+# Azure + AWS + Local
+# ======================================================
+
+set -euo pipefail
+
+TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
+LOG_FILE="emergency_shutdown_${TIMESTAMP}.log"
+ARTIFACT_DIR="${TMPDIR:-/tmp}/emergency_shutdown_${TIMESTAMP}"
+DRY_RUN=false
+CONFIRMED=false
+FORCE_LOCAL_SHUTDOWN=false
+KEEP_ARTIFACTS=false
+AWS_REGION=""
+AZ_SUBSCRIPTION=""
+
+usage() {
+    cat <<USAGE
+Usage: $0 [options]
+
+Options:
+  --dry-run                Print actions without executing them.
+  --force                  Skip interactive confirmation.
+  --force-local-shutdown   Allow local machine shutdown execution.
+  --keep-artifacts         Keep collected snapshots under artifact directory.
+  --aws-region <region>    Scope AWS actions to a specific region.
+  --az-subscription <id>   Scope Azure actions to a specific subscription.
+  --help                   Show this help text.
+USAGE
+}
+
+log() {
+    local msg="$1"
+    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $msg" | tee -a "$LOG_FILE"
+}
+
+run() {
+    if $DRY_RUN; then
+        log "[DRY RUN] $*"
+        return 0
+    fi
+
+    log "[EXEC] $*"
+    "$@"
+}
+
+run_capture() {
+    local output_file="$1"
+    shift
+
+    if $DRY_RUN; then
+        log "[DRY RUN] $* > $output_file"
+        return 0
+    fi
+
+    log "[EXEC] $* > $output_file"
+    "$@" >"$output_file"
+}
+
+cleanup() {
+    if [[ -d "$ARTIFACT_DIR" ]] && ! $KEEP_ARTIFACTS; then
+        rm -rf "$ARTIFACT_DIR"
+        log "Ephemeral artifacts removed: $ARTIFACT_DIR"
+    fi
+}
+
+confirm() {
+    read -rp "Type 'CONFIRM' to proceed with emergency shutdown: " input
+    if [[ "$input" == "CONFIRM" ]]; then
+        CONFIRMED=true
+    else
+        log "Confirmation failed. Exiting."
+        exit 1
+    fi
+}
+
+check_dependencies() {
+    local missing=()
+    for cmd in az aws xargs; do
+        command -v "$cmd" >/dev/null || missing+=("$cmd")
+    done
+
+    if ((${#missing[@]} > 0)); then
+        printf 'Missing required command(s): %s\n' "${missing[*]}" >&2
+        exit 1
+    fi
+}
+
+validate_sessions() {
+    log "Validating Azure/AWS sessions..."
+    run az account show >/dev/null
+    run aws sts get-caller-identity >/dev/null
+}
+
+parse_args() {
+    while [[ $# -gt 0 ]]; do
+        case "$1" in
+            --dry-run)
+                DRY_RUN=true
+                ;;
+            --force)
+                CONFIRMED=true
+                ;;
+            --force-local-shutdown)
+                FORCE_LOCAL_SHUTDOWN=true
+                ;;
+            --keep-artifacts)
+                KEEP_ARTIFACTS=true
+                ;;
+            --aws-region)
+                AWS_REGION="${2:-}"
+                shift
+                ;;
+            --az-subscription)
+                AZ_SUBSCRIPTION="${2:-}"
+                shift
+                ;;
+            --help|-h)
+                usage
+                exit 0
+                ;;
+            *)
+                printf 'Unknown argument: %s\n' "$1" >&2
+                usage
+                exit 1
+                ;;
+        esac
+        shift
+    done
+}
+
+apply_scope() {
+    if [[ -n "$AZ_SUBSCRIPTION" ]]; then
+        log "Applying Azure subscription scope: $AZ_SUBSCRIPTION"
+        run az account set --subscription "$AZ_SUBSCRIPTION"
+    fi
+
+    if [[ -n "$AWS_REGION" ]]; then
+        export AWS_DEFAULT_REGION="$AWS_REGION"
+        log "Applying AWS region scope: $AWS_REGION"
+    fi
+}
+
+audit_state() {
+    mkdir -p "$ARTIFACT_DIR"
+
+    log "Capturing Azure VM inventory..."
+    run_capture "$ARTIFACT_DIR/azure_vm_snapshot.txt" az vm list -o table
+
+    log "Capturing AWS EC2 inventory..."
+    run_capture "$ARTIFACT_DIR/aws_ec2_snapshot.json" aws ec2 describe-instances
+
+    log "Capturing local process state..."
+    run_capture "$ARTIFACT_DIR/local_process_snapshot.txt" ps aux
+}
+
+azure_shutdown() {
+    log "Stopping Azure VMs..."
+    if $DRY_RUN; then
+        log "[DRY RUN] az vm stop --ids \\$(az vm list --query '[].id' -o tsv)"
+    else
+        mapfile -t vm_ids < <(az vm list --query '[].id' -o tsv)
+        if ((${#vm_ids[@]} == 0)); then
+            log "No Azure VMs found."
+        else
+            run az vm stop --ids "${vm_ids[@]}"
+        fi
+    fi
+
+    log "Tagging Azure Public IPs to disabled state context..."
+    if $DRY_RUN; then
+        log "[DRY RUN] az network public-ip update --ids <id> --set tags.emergencyDisabled=true"
+    else
+        mapfile -t pip_ids < <(az network public-ip list --query '[].id' -o tsv)
+        for pip in "${pip_ids[@]}"; do
+            run az network public-ip update --ids "$pip" --set tags.emergencyDisabled=true
+        done
+    fi
+}
+
+aws_shutdown() {
+    log "Stopping AWS EC2 instances..."
+    if $DRY_RUN; then
+        log "[DRY RUN] aws ec2 stop-instances --instance-ids \\$(aws ec2 describe-instances --query 'Reservations[].Instances[].InstanceId' --output text)"
+    else
+        instance_ids=$(aws ec2 describe-instances --query 'Reservations[].Instances[].InstanceId' --output text)
+        if [[ -z "$instance_ids" || "$instance_ids" == "None" ]]; then
+            log "No AWS EC2 instances found."
+        else
+            # shellcheck disable=SC2086
+            run aws ec2 stop-instances --instance-ids $instance_ids
+        fi
+    fi
+
+    log "Detaching AWS Internet Gateways..."
+    if $DRY_RUN; then
+        log "[DRY RUN] iterate IGWs and detach from attached VPCs"
+        return 0
+    fi
+
+    IGWS=$(aws ec2 describe-internet-gateways --query 'InternetGateways[].InternetGatewayId' --output text)
+    if [[ -z "$IGWS" || "$IGWS" == "None" ]]; then
+        log "No Internet Gateways found."
+        return 0
+    fi
+
+    for igw in $IGWS; do
+        VPCS=$(aws ec2 describe-internet-gateways --internet-gateway-ids "$igw" \
+            --query 'InternetGateways[].Attachments[].VpcId' --output text)
+        for vpc in $VPCS; do
+            run aws ec2 detach-internet-gateway --internet-gateway-id "$igw" --vpc-id "$vpc"
+        done
+    done
+}
+
+revoke_credentials() {
+    log "Revoking AWS IAM access keys..."
+    if $DRY_RUN; then
+        log "[DRY RUN] Enumerate users/keys and deactivate each key"
+    else
+        mapfile -t users < <(aws iam list-users --query 'Users[].UserName' --output text)
+        for user in "${users[@]}"; do
+            [[ -z "$user" ]] && continue
+            mapfile -t keys < <(aws iam list-access-keys --user-name "$user" --query 'AccessKeyMetadata[].AccessKeyId' --output text)
+            for key in "${keys[@]}"; do
+                [[ -z "$key" ]] && continue
+                run aws iam update-access-key --access-key-id "$key" --status Inactive --user-name "$user"
+            done
+        done
+    fi
+
+    log "Disabling Azure user accounts..."
+    if $DRY_RUN; then
+        log "[DRY RUN] Enumerate Azure users and disable accounts"
+    else
+        mapfile -t users < <(az ad user list --query '[].userPrincipalName' -o tsv)
+        for user in "${users[@]}"; do
+            [[ -z "$user" ]] && continue
+            run az ad user update --id "$user" --account-enabled false
+        done
+    fi
+}
+
+network_isolation_local() {
+    log "Blocking outbound network traffic locally..."
+    if [[ "$OSTYPE" == linux-gnu* ]]; then
+        run sudo ufw default deny outgoing
+    else
+        log "Local outbound firewall isolation skipped for OSTYPE=$OSTYPE"
+    fi
+}
+
+local_shutdown() {
+    if ! $FORCE_LOCAL_SHUTDOWN; then
+        log "Local shutdown skipped (use --force-local-shutdown to enable)."
+        return 0
+    fi
+
+    log "Initiating local shutdown..."
+    if [[ "$OSTYPE" == linux-gnu* ]]; then
+        run sudo poweroff
+    elif [[ "$OSTYPE" == darwin* ]]; then
+        run sudo shutdown -h now
+    elif [[ "$OSTYPE" == msys* || "$OSTYPE" == win32 ]]; then
+        run shutdown /s /t 0 /f
+    else
+        log "Unsupported OSTYPE for shutdown: $OSTYPE"
+    fi
+}
+
+main() {
+    parse_args "$@"
+    check_dependencies
+    trap cleanup EXIT
+
+    log "Emergency shutdown initiated."
+
+    apply_scope
+    validate_sessions
+
+    if ! $CONFIRMED; then
+        confirm
+    fi
+
+    audit_state
+    azure_shutdown
+    aws_shutdown
+    revoke_credentials
+    network_isolation_local
+
+    log "Cloud response actions completed."
+    local_shutdown
+
+    if $KEEP_ARTIFACTS; then
+        log "Artifacts retained at: $ARTIFACT_DIR"
+    fi
+}
+
+main "$@"
diff --git a/ephemeral_multicloud_emergency_shutdown.sh b/ephemeral_multicloud_emergency_shutdown.sh
new file mode 100755
index 0000000000000000000000000000000000000000..0e361fb6cc48fd1aabb2912526e0c9daa73f35d6
--- /dev/null
+++ b/ephemeral_multicloud_emergency_shutdown.sh
@@ -0,0 +1,284 @@
+#!/usr/bin/env bash
+
+# ======================================================
+# EPHEMERAL MULTI-CLOUD EMERGENCY SHUTDOWN ORCHESTRATOR
+# Azure + AWS + Local (safer, scoped, auditable)
+# ======================================================
+
+set -euo pipefail
+
+SCRIPT_NAME="$(basename "$0")"
+TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
+RUN_ID="shutdown-${TIMESTAMP}-$$"
+ARTIFACT_DIR="$(mktemp -d -t emergency_shutdown_${TIMESTAMP}_XXXX)"
+LOG_FILE="${ARTIFACT_DIR}/emergency_shutdown.log"
+
+DRY_RUN=true
+CONFIRMED=false
+FORCE=false
+KEEP_ARTIFACTS=false
+NO_LOCAL_SHUTDOWN=false
+DISABLE_CREDENTIAL_REVOCATION=false
+TARGET_TAG_KEY=""
+TARGET_TAG_VALUE=""
+AWS_PROFILE=""
+AZURE_SUBSCRIPTION=""
+
+cleanup() {
+  if [[ "${KEEP_ARTIFACTS}" == "false" ]]; then
+    rm -rf "${ARTIFACT_DIR}"
+  else
+    log "Keeping artifacts at: ${ARTIFACT_DIR}"
+  fi
+}
+trap cleanup EXIT
+
+log() {
+  local level="$1"
+  shift
+  local message="$*"
+  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] [$level] $message" | tee -a "$LOG_FILE"
+}
+
+die() {
+  log "ERROR" "$*"
+  exit 1
+}
+
+usage() {
+  cat <<USAGE
+Usage: ${SCRIPT_NAME} [options]
+
+Defaults to --dry-run for safety.
+
+Options:
+  --execute                         Perform real actions (disable dry-run)
+  --dry-run                         Print actions only (default)
+  --force                           Skip confirmation prompt
+  --keep-artifacts                  Keep logs and snapshots after exit
+  --no-local-shutdown               Do not power off local machine
+  --disable-credential-revocation   Skip IAM/AAD credential revocation
+  --tag-key <key>                   Restrict operations to resources with tag key
+  --tag-value <value>               Restrict operations to resources with tag value
+  --aws-profile <profile>           Use AWS named profile
+  --azure-subscription <id|name>    Use Azure subscription
+  -h, --help                        Show help
+USAGE
+}
+
+run() {
+  local cmd="$*"
+  if [[ "${DRY_RUN}" == "true" ]]; then
+    log "DRYRUN" "$cmd"
+  else
+    log "EXEC" "$cmd"
+    eval "$cmd"
+  fi
+}
+
+confirm() {
+  local token="CONFIRM-${RUN_ID}"
+  echo
+  echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
+  echo "Emergency shutdown will stop cloud resources and isolate hosts."
+  echo "Run ID: ${RUN_ID}"
+  echo "Type exactly: ${token}"
+  echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
+  read -r input
+  if [[ "$input" == "$token" ]]; then
+    CONFIRMED=true
+  else
+    die "Confirmation failed. Exiting."
+  fi
+}
+
+check_dependencies() {
+  command -v az >/dev/null || die "Azure CLI missing"
+  command -v aws >/dev/null || die "AWS CLI missing"
+  command -v jq >/dev/null || log "WARN" "jq not found; continuing without JSON pretty-printing"
+}
+
+parse_args() {
+  while [[ $# -gt 0 ]]; do
+    case "$1" in
+      --execute) DRY_RUN=false ;;
+      --dry-run) DRY_RUN=true ;;
+      --force) FORCE=true ; CONFIRMED=true ;;
+      --keep-artifacts) KEEP_ARTIFACTS=true ;;
+      --no-local-shutdown) NO_LOCAL_SHUTDOWN=true ;;
+      --disable-credential-revocation) DISABLE_CREDENTIAL_REVOCATION=true ;;
+      --tag-key)
+        TARGET_TAG_KEY="${2:-}"; shift ;;
+      --tag-value)
+        TARGET_TAG_VALUE="${2:-}"; shift ;;
+      --aws-profile)
+        AWS_PROFILE="${2:-}"; shift ;;
+      --azure-subscription)
+        AZURE_SUBSCRIPTION="${2:-}"; shift ;;
+      -h|--help)
+        usage; exit 0 ;;
+      *)
+        die "Unknown argument: $1" ;;
+    esac
+    shift
+  done
+
+  if [[ -n "$TARGET_TAG_KEY" && -z "$TARGET_TAG_VALUE" ]]; then
+    die "--tag-key requires --tag-value"
+  fi
+}
+
+configure_context() {
+  if [[ -n "$AWS_PROFILE" ]]; then
+    export AWS_PROFILE
+    log "INFO" "Using AWS profile: ${AWS_PROFILE}"
+  fi
+  if [[ -n "$AZURE_SUBSCRIPTION" ]]; then
+    run "az account set --subscription \"${AZURE_SUBSCRIPTION}\""
+  fi
+}
+
+aws_instance_query() {
+  if [[ -n "$TARGET_TAG_KEY" ]]; then
+    echo "Reservations[].Instances[?Tags[?Key=='${TARGET_TAG_KEY}' && Value=='${TARGET_TAG_VALUE}']].InstanceId"
+  else
+    echo "Reservations[].Instances[].InstanceId"
+  fi
+}
+
+azure_vm_query() {
+  if [[ -n "$TARGET_TAG_KEY" ]]; then
+    echo "[?tags.${TARGET_TAG_KEY}=='${TARGET_TAG_VALUE}'].id"
+  else
+    echo "[].id"
+  fi
+}
+
+audit_state() {
+  log "INFO" "Capturing Azure VM inventory..."
+  run "az vm list -d -o json > '${ARTIFACT_DIR}/azure_vm_snapshot.json'"
+
+  log "INFO" "Capturing AWS EC2 inventory..."
+  run "aws ec2 describe-instances > '${ARTIFACT_DIR}/aws_ec2_snapshot.json'"
+
+  log "INFO" "Capturing local process state..."
+  run "ps aux > '${ARTIFACT_DIR}/local_process_snapshot.txt'"
+}
+
+azure_shutdown() {
+  log "INFO" "Stopping Azure VMs..."
+  local ids
+  ids="$(az vm list --query "$(azure_vm_query)" -o tsv || true)"
+  if [[ -z "$ids" ]]; then
+    log "INFO" "No Azure VMs matched scope."
+  else
+    run "az vm stop --ids $ids"
+  fi
+
+  log "INFO" "Converting Azure public IPs to static (containment mode)..."
+  local ip_ids
+  if [[ -n "$TARGET_TAG_KEY" ]]; then
+    ip_ids="$(az network public-ip list --query "[?tags.${TARGET_TAG_KEY}=='${TARGET_TAG_VALUE}'].id" -o tsv || true)"
+  else
+    ip_ids="$(az network public-ip list --query "[].id" -o tsv || true)"
+  fi
+  if [[ -n "$ip_ids" ]]; then
+    while IFS= read -r ip; do
+      [[ -z "$ip" ]] && continue
+      run "az network public-ip update --ids '$ip' --allocation-method Static"
+    done <<< "$ip_ids"
+  else
+    log "INFO" "No Azure public IPs matched scope."
+  fi
+}
+
+aws_shutdown() {
+  log "INFO" "Stopping AWS EC2 instances..."
+  local query ids
+  query="$(aws_instance_query)"
+  ids="$(aws ec2 describe-instances --query "$query" --output text | tr '\t' ' ' | xargs || true)"
+  if [[ -z "$ids" || "$ids" == "None" ]]; then
+    log "INFO" "No AWS instances matched scope."
+  else
+    run "aws ec2 stop-instances --instance-ids $ids"
+  fi
+
+  log "INFO" "Detaching Internet Gateways from VPCs..."
+  local igws
+  igws="$(aws ec2 describe-internet-gateways --query 'InternetGateways[].InternetGatewayId' --output text || true)"
+  for igw in $igws; do
+    [[ -z "$igw" || "$igw" == "None" ]] && continue
+    local vpcs
+    vpcs="$(aws ec2 describe-internet-gateways --internet-gateway-ids "$igw" --query 'InternetGateways[].Attachments[].VpcId' --output text || true)"
+    for vpc in $vpcs; do
+      [[ -z "$vpc" || "$vpc" == "None" ]] && continue
+      run "aws ec2 detach-internet-gateway --internet-gateway-id '$igw' --vpc-id '$vpc'"
+    done
+  done
+}
+
+revoke_credentials() {
+  if [[ "$DISABLE_CREDENTIAL_REVOCATION" == "true" ]]; then
+    log "WARN" "Skipping credential revocation by request."
+    return
+  fi
+
+  log "INFO" "Revoking AWS IAM access keys..."
+  run "aws iam list-users --query 'Users[].UserName' --output text | xargs -n1 -I{} aws iam list-access-keys --user-name {} --query 'AccessKeyMetadata[].AccessKeyId' --output text | xargs -n1 -I{} aws iam update-access-key --access-key-id {} --status Inactive"
+
+  log "INFO" "Disabling Azure user accounts..."
+  run "az ad user list --query '[].userPrincipalName' -o tsv | xargs -n1 -I{} az ad user update --id {} --account-enabled false"
+}
+
+network_isolation_local() {
+  log "INFO" "Blocking outbound network traffic locally (Linux/UFW only)..."
+  if [[ "${OSTYPE}" == linux-gnu* ]] && command -v ufw >/dev/null; then
+    run "sudo ufw --force default deny outgoing"
+  else
+    log "WARN" "Local network isolation skipped for this OS or missing ufw."
+  fi
+}
+
+local_shutdown() {
+  if [[ "$NO_LOCAL_SHUTDOWN" == "true" ]]; then
+    log "WARN" "Local shutdown skipped (--no-local-shutdown)."
+    return
+  fi
+
+  log "INFO" "Initiating local shutdown..."
+  if [[ "${OSTYPE}" == linux-gnu* ]]; then
+    run "sudo poweroff"
+  elif [[ "${OSTYPE}" == darwin* ]]; then
+    run "sudo shutdown -h now"
+  elif [[ "${OSTYPE}" == msys* || "${OSTYPE}" == win32 ]]; then
+    run "shutdown /s /t 0 /f"
+  else
+    log "WARN" "Unknown OS type; local shutdown skipped."
+  fi
+}
+
+main() {
+  parse_args "$@"
+  check_dependencies
+  configure_context
+
+  log "INFO" "Emergency shutdown initiated. Run ID: ${RUN_ID}"
+  log "INFO" "Artifacts path: ${ARTIFACT_DIR}"
+  log "INFO" "Mode: $([[ "$DRY_RUN" == "true" ]] && echo DRY-RUN || echo EXECUTE)"
+
+  if [[ "$FORCE" != "true" && "$CONFIRMED" != "true" ]]; then
+    confirm
+  fi
+
+  audit_state
+  azure_shutdown
+  aws_shutdown
+  revoke_credentials
+  network_isolation_local
+
+  log "INFO" "Cloud shutdown sequence completed. Proceeding to local shutdown stage..."
+  local_shutdown
+  log "INFO" "Run complete."
+}
+
+main "$@"
diff --git a/emergency_shutdown_orchestrator.sh b/emergency_shutdown_orchestrator.sh
new file mode 100755
index 0000000000000000000000000000000000000000..c1a5fbd09c9fd626de003644ffb1c1ebc66e9144
--- /dev/null
+++ b/emergency_shutdown_orchestrator.sh
@@ -0,0 +1,246 @@
+#!/usr/bin/env bash
+
+# ======================================================
+# EPHEMERAL MULTI-CLOUD EMERGENCY SHUTDOWN ORCHESTRATOR
+# Azure + AWS + Local
+# ======================================================
+
+set -euo pipefail
+
+LOG_FILE="emergency_shutdown_$(date +%Y%m%d_%H%M%S).log"
+DRY_RUN=false
+CONFIRMED=false
+SKIP_AZURE=false
+SKIP_AWS=false
+SKIP_LOCAL=false
+SKIP_CREDS=false
+SKIP_NETWORK=false
+
+AWS_REGION="${AWS_REGION:-}"
+AWS_PROFILE="${AWS_PROFILE:-}"
+AZ_SUBSCRIPTION="${AZ_SUBSCRIPTION:-}"
+
+usage() {
+  cat <<'USAGE'
+Usage: emergency_shutdown_orchestrator.sh [options]
+
+Options:
+  --dry-run            Print actions without executing.
+  --force              Skip interactive confirmation.
+  --skip-azure         Skip Azure shutdown actions.
+  --skip-aws           Skip AWS shutdown actions.
+  --skip-creds         Skip credential revocation actions.
+  --skip-network       Skip local network isolation actions.
+  --skip-local         Skip local machine shutdown.
+  --aws-region REGION  Set AWS region for command execution.
+  --aws-profile NAME   Set AWS profile for command execution.
+  --az-sub SUB_ID      Set Azure subscription before actions.
+  -h, --help           Show this help text.
+USAGE
+}
+
+log() {
+  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $1" | tee -a "$LOG_FILE"
+}
+
+run() {
+  local cmd="$1"
+  if $DRY_RUN; then
+    log "[DRY RUN] $cmd"
+  else
+    log "[EXEC] $cmd"
+    bash -lc "$cmd"
+  fi
+}
+
+confirm() {
+  read -rp "Type 'CONFIRM' to proceed: " input
+  if [[ "$input" == "CONFIRM" ]]; then
+    CONFIRMED=true
+  else
+    log "Confirmation failed. Exiting."
+    exit 1
+  fi
+}
+
+check_dependencies() {
+  if ! $SKIP_AZURE; then
+    command -v az >/dev/null || { echo "Azure CLI missing"; exit 1; }
+  fi
+
+  if ! $SKIP_AWS; then
+    command -v aws >/dev/null || { echo "AWS CLI missing"; exit 1; }
+  fi
+
+  if ! $SKIP_NETWORK || ! $SKIP_LOCAL; then
+    command -v sudo >/dev/null || { echo "sudo missing"; exit 1; }
+  fi
+}
+
+parse_args() {
+  while [[ $# -gt 0 ]]; do
+    case "$1" in
+      --dry-run) DRY_RUN=true ;;
+      --force) CONFIRMED=true ;;
+      --skip-azure) SKIP_AZURE=true ;;
+      --skip-aws) SKIP_AWS=true ;;
+      --skip-creds) SKIP_CREDS=true ;;
+      --skip-network) SKIP_NETWORK=true ;;
+      --skip-local) SKIP_LOCAL=true ;;
+      --aws-region)
+        AWS_REGION="${2:-}"
+        shift
+        ;;
+      --aws-profile)
+        AWS_PROFILE="${2:-}"
+        shift
+        ;;
+      --az-sub)
+        AZ_SUBSCRIPTION="${2:-}"
+        shift
+        ;;
+      -h|--help)
+        usage
+        exit 0
+        ;;
+      *)
+        echo "Unknown argument: $1"
+        usage
+        exit 1
+        ;;
+    esac
+    shift
+  done
+}
+
+aws_base() {
+  local cmd="aws"
+  [[ -n "$AWS_REGION" ]] && cmd+=" --region $AWS_REGION"
+  [[ -n "$AWS_PROFILE" ]] && cmd+=" --profile $AWS_PROFILE"
+  echo "$cmd"
+}
+
+prepare_context() {
+  if ! $SKIP_AZURE && [[ -n "$AZ_SUBSCRIPTION" ]]; then
+    run "az account set --subscription '$AZ_SUBSCRIPTION'"
+  fi
+}
+
+audit_state() {
+  log "Capturing state snapshots..."
+
+  if ! $SKIP_AZURE; then
+    run "az vm list -o table > azure_vm_snapshot.txt"
+  fi
+
+  if ! $SKIP_AWS; then
+    local aws_cmd
+    aws_cmd="$(aws_base)"
+    run "$aws_cmd ec2 describe-instances > aws_ec2_snapshot.json"
+  fi
+
+  run "ps aux > local_process_snapshot.txt"
+}
+
+azure_shutdown() {
+  $SKIP_AZURE && return 0
+
+  log "Stopping Azure VMs..."
+  run "az vm stop --ids \$(az vm list --query '[].id' -o tsv)"
+
+  log "Disabling Azure Public IPs (switching to static allocation)..."
+  run "az network public-ip list --query '[].id' -o tsv | xargs -r -I{} az network public-ip update --ids {} --allocation-method Static"
+}
+
+aws_shutdown() {
+  $SKIP_AWS && return 0
+
+  local aws_cmd
+  aws_cmd="$(aws_base)"
+
+  log "Stopping AWS EC2 instances..."
+  run "$aws_cmd ec2 stop-instances --instance-ids \$($aws_cmd ec2 describe-instances --query 'Reservations[].Instances[].InstanceId' --output text)"
+
+  log "Detaching Internet Gateways..."
+  local igws
+  igws=$(bash -lc "$aws_cmd ec2 describe-internet-gateways --query 'InternetGateways[].InternetGatewayId' --output text")
+  for igw in $igws; do
+    local vpcs
+    vpcs=$(bash -lc "$aws_cmd ec2 describe-internet-gateways --internet-gateway-ids '$igw' --query 'InternetGateways[].Attachments[].VpcId' --output text")
+    for vpc in $vpcs; do
+      run "$aws_cmd ec2 detach-internet-gateway --internet-gateway-id $igw --vpc-id $vpc"
+    done
+  done
+}
+
+revoke_credentials() {
+  $SKIP_CREDS && return 0
+
+  if ! $SKIP_AWS; then
+    local aws_cmd
+    aws_cmd="$(aws_base)"
+
+    log "Revoking AWS IAM access keys..."
+    run "$aws_cmd iam list-users --query 'Users[].UserName' --output text | xargs -r -n1 -I{} $aws_cmd iam list-access-keys --user-name {} --query 'AccessKeyMetadata[].AccessKeyId' --output text | xargs -r -n1 -I{} $aws_cmd iam update-access-key --access-key-id {} --status Inactive"
+  fi
+
+  if ! $SKIP_AZURE; then
+    log "Disabling Azure user accounts..."
+    run "az ad user list --query '[].userPrincipalName' -o tsv | xargs -r -n1 -I{} az ad user update --id {} --account-enabled false"
+  fi
+}
+
+network_isolation_local() {
+  $SKIP_NETWORK && return 0
+
+  log "Blocking outbound network traffic locally..."
+  if [[ "$OSTYPE" == linux-gnu* ]]; then
+    run "sudo ufw default deny outgoing"
+  else
+    log "Local network isolation not implemented for OSTYPE=$OSTYPE"
+  fi
+}
+
+local_shutdown() {
+  $SKIP_LOCAL && return 0
+
+  log "Initiating local shutdown..."
+  if [[ "$OSTYPE" == linux-gnu* ]]; then
+    run "sudo poweroff"
+  elif [[ "$OSTYPE" == darwin* ]]; then
+    run "sudo shutdown -h now"
+  elif [[ "$OSTYPE" == msys* || "$OSTYPE" == win32 ]]; then
+    run "shutdown /s /t 0 /f"
+  else
+    log "Unsupported OSTYPE for auto-shutdown: $OSTYPE"
+  fi
+}
+
+summary() {
+  log "Summary: dry_run=$DRY_RUN, skip_azure=$SKIP_AZURE, skip_aws=$SKIP_AWS, skip_creds=$SKIP_CREDS, skip_network=$SKIP_NETWORK, skip_local=$SKIP_LOCAL"
+}
+
+main() {
+  parse_args "$@"
+  check_dependencies
+  prepare_context
+
+  log "Emergency shutdown initiated."
+  summary
+
+  if ! $CONFIRMED; then
+    confirm
+  fi
+
+  audit_state
+  azure_shutdown
+  aws_shutdown
+  revoke_credentials
+  network_isolation_local
+
+  log "Cloud systems halted. Proceeding to local shutdown..."
+  local_shutdown
+  log "Sequence complete."
+}
+
+main "$@"
diff --git a/emergency_shutdown_orchestrator.sh b/emergency_shutdown_orchestrator.sh
new file mode 100755
index 0000000000000000000000000000000000000000..5566d8b80444e9d352af1cd47b475978d76d702e
--- /dev/null
+++ b/emergency_shutdown_orchestrator.sh
@@ -0,0 +1,305 @@
+#!/usr/bin/env bash
+
+# ======================================================
+# EPHEMERAL MULTI-CLOUD EMERGENCY SHUTDOWN ORCHESTRATOR
+# Azure + AWS + Local
+# ======================================================
+
+set -euo pipefail
+
+SCRIPT_NAME="$(basename "$0")"
+TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
+LOG_FILE="emergency_shutdown_${TIMESTAMP}.log"
+AZURE_VM_SNAPSHOT="azure_vm_snapshot_${TIMESTAMP}.json"
+AWS_EC2_SNAPSHOT="aws_ec2_snapshot_${TIMESTAMP}.json"
+LOCAL_PROCESS_SNAPSHOT="local_process_snapshot_${TIMESTAMP}.txt"
+
+DRY_RUN=false
+CONFIRMED=false
+SKIP_LOCAL_SHUTDOWN=false
+SKIP_CREDENTIAL_REVOCATION=false
+AZURE_RESOURCE_GROUP=""
+AWS_REGION=""
+
+log() {
+  echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" | tee -a "$LOG_FILE"
+}
+
+die() {
+  log "ERROR: $*"
+  exit 1
+}
+
+run_cmd() {
+  if $DRY_RUN; then
+    log "[DRY RUN] $*"
+    return 0
+  fi
+
+  log "[EXEC] $*"
+  "$@"
+}
+
+run_shell() {
+  if $DRY_RUN; then
+    log "[DRY RUN] $*"
+    return 0
+  fi
+
+  log "[EXEC] $*"
+  bash -c "$*"
+}
+
+on_error() {
+  local exit_code=$?
+  log "Failure detected (exit code: ${exit_code}). Review ${LOG_FILE} and snapshots for audit."
+  exit "$exit_code"
+}
+trap on_error ERR
+
+usage() {
+  cat <<USAGE
+Usage: ${SCRIPT_NAME} [OPTIONS]
+
+Options:
+  --dry-run                          Print actions without executing.
+  --force                            Skip interactive confirmation prompt.
+  --skip-local-shutdown              Do not power off the local machine.
+  --skip-credential-revocation       Skip AWS/Azure credential revocation.
+  --azure-resource-group <name>      Restrict Azure VM operations to one resource group.
+  --aws-region <region>              Restrict AWS operations to one region.
+  -h, --help                         Show this help.
+USAGE
+}
+
+check_dependencies() {
+  command -v az >/dev/null || die "Azure CLI missing"
+  command -v aws >/dev/null || die "AWS CLI missing"
+  command -v jq >/dev/null || die "jq missing"
+}
+
+parse_args() {
+  while [[ $# -gt 0 ]]; do
+    case "$1" in
+      --dry-run)
+        DRY_RUN=true
+        ;;
+      --force)
+        CONFIRMED=true
+        ;;
+      --skip-local-shutdown)
+        SKIP_LOCAL_SHUTDOWN=true
+        ;;
+      --skip-credential-revocation)
+        SKIP_CREDENTIAL_REVOCATION=true
+        ;;
+      --azure-resource-group)
+        shift
+        [[ $# -gt 0 ]] || die "Missing value for --azure-resource-group"
+        AZURE_RESOURCE_GROUP="$1"
+        ;;
+      --aws-region)
+        shift
+        [[ $# -gt 0 ]] || die "Missing value for --aws-region"
+        AWS_REGION="$1"
+        ;;
+      -h|--help)
+        usage
+        exit 0
+        ;;
+      *)
+        die "Unknown argument: $1"
+        ;;
+    esac
+    shift
+  done
+}
+
+confirm() {
+  cat <<PROMPT
+
+!!! EMERGENCY SHUTDOWN ORCHESTRATOR !!!
+This action can stop cloud compute, isolate networking, disable credentials,
+and optionally shut down this local host.
+PROMPT
+
+  read -rp "Type 'CONFIRM' to proceed: " input
+  if [[ "$input" == "CONFIRM" ]]; then
+    CONFIRMED=true
+  else
+    die "Confirmation failed. Exiting."
+  fi
+}
+
+audit_state() {
+  log "Capturing Azure VM inventory..."
+  if [[ -n "$AZURE_RESOURCE_GROUP" ]]; then
+    run_cmd az vm list --resource-group "$AZURE_RESOURCE_GROUP" -o json > "$AZURE_VM_SNAPSHOT"
+  else
+    run_cmd az vm list -o json > "$AZURE_VM_SNAPSHOT"
+  fi
+
+  log "Capturing AWS EC2 inventory..."
+  if [[ -n "$AWS_REGION" ]]; then
+    run_cmd aws ec2 describe-instances --region "$AWS_REGION" > "$AWS_EC2_SNAPSHOT"
+  else
+    run_cmd aws ec2 describe-instances > "$AWS_EC2_SNAPSHOT"
+  fi
+
+  log "Capturing local process state..."
+  run_cmd ps aux > "$LOCAL_PROCESS_SNAPSHOT"
+}
+
+azure_shutdown() {
+  log "Stopping Azure VMs..."
+  local vm_ids
+  if [[ -n "$AZURE_RESOURCE_GROUP" ]]; then
+    vm_ids="$(az vm list --resource-group "$AZURE_RESOURCE_GROUP" --query '[].id' -o tsv)"
+  else
+    vm_ids="$(az vm list --query '[].id' -o tsv)"
+  fi
+
+  if [[ -z "$vm_ids" ]]; then
+    log "No Azure VMs found."
+  else
+    while IFS= read -r vm_id; do
+      [[ -n "$vm_id" ]] || continue
+      run_cmd az vm stop --ids "$vm_id"
+    done <<< "$vm_ids"
+  fi
+
+  log "Converting Azure Public IP allocation to static (containment posture)..."
+  local pip_ids
+  pip_ids="$(az network public-ip list --query '[].id' -o tsv)"
+  if [[ -z "$pip_ids" ]]; then
+    log "No Azure Public IP resources found."
+  else
+    while IFS= read -r pip_id; do
+      [[ -n "$pip_id" ]] || continue
+      run_cmd az network public-ip update --ids "$pip_id" --allocation-method Static
+    done <<< "$pip_ids"
+  fi
+}
+
+aws_shutdown() {
+  log "Stopping AWS EC2 instances..."
+  local aws_region_args=()
+  if [[ -n "$AWS_REGION" ]]; then
+    aws_region_args=(--region "$AWS_REGION")
+  fi
+
+  local instance_ids
+  instance_ids="$(aws ec2 describe-instances "${aws_region_args[@]}" --query 'Reservations[].Instances[].InstanceId' --output text)"
+  if [[ -z "$instance_ids" || "$instance_ids" == "None" ]]; then
+    log "No AWS EC2 instances found."
+  else
+    run_shell "aws ec2 stop-instances ${AWS_REGION:+--region $AWS_REGION }--instance-ids $instance_ids"
+  fi
+
+  log "Detaching AWS Internet Gateways..."
+  local igws
+  igws="$(aws ec2 describe-internet-gateways "${aws_region_args[@]}" --query 'InternetGateways[].InternetGatewayId' --output text)"
+  if [[ -z "$igws" || "$igws" == "None" ]]; then
+    log "No Internet Gateways found."
+    return
+  fi
+
+  local igw vpcs vpc
+  for igw in $igws; do
+    vpcs="$(aws ec2 describe-internet-gateways "${aws_region_args[@]}" --internet-gateway-ids "$igw" --query 'InternetGateways[].Attachments[].VpcId' --output text)"
+    for vpc in $vpcs; do
+      [[ -n "$vpc" && "$vpc" != "None" ]] || continue
+      run_cmd aws ec2 detach-internet-gateway "${aws_region_args[@]}" --internet-gateway-id "$igw" --vpc-id "$vpc"
+    done
+  done
+}
+
+revoke_credentials() {
+  if $SKIP_CREDENTIAL_REVOCATION; then
+    log "Skipping credential revocation by request."
+    return
+  fi
+
+  log "Revoking AWS IAM access keys..."
+  local users
+  users="$(aws iam list-users --query 'Users[].UserName' --output text)"
+  if [[ -z "$users" || "$users" == "None" ]]; then
+    log "No IAM users found."
+  else
+    local user access_keys key_id
+    for user in $users; do
+      access_keys="$(aws iam list-access-keys --user-name "$user" --query 'AccessKeyMetadata[].AccessKeyId' --output text)"
+      for key_id in $access_keys; do
+        [[ -n "$key_id" && "$key_id" != "None" ]] || continue
+        run_cmd aws iam update-access-key --user-name "$user" --access-key-id "$key_id" --status Inactive
+      done
+    done
+  fi
+
+  log "Disabling Azure user accounts..."
+  local azure_users
+  azure_users="$(az ad user list --query '[].userPrincipalName' -o tsv)"
+  if [[ -z "$azure_users" ]]; then
+    log "No Azure users found."
+  else
+    local principal
+    for principal in $azure_users; do
+      run_cmd az ad user update --id "$principal" --account-enabled false
+    done
+  fi
+}
+
+network_isolation_local() {
+  log "Blocking outbound network traffic locally when supported..."
+  if [[ "$OSTYPE" == linux-gnu* ]]; then
+    if command -v ufw >/dev/null; then
+      run_cmd sudo ufw default deny outgoing
+    else
+      log "ufw not installed; skipping Linux outbound firewall lockdown."
+    fi
+  else
+    log "Local network isolation not implemented for OSTYPE=$OSTYPE"
+  fi
+}
+
+local_shutdown() {
+  if $SKIP_LOCAL_SHUTDOWN; then
+    log "Skipping local shutdown by request."
+    return
+  fi
+
+  log "Initiating local shutdown..."
+  if [[ "$OSTYPE" == linux-gnu* ]]; then
+    run_cmd sudo poweroff
+  elif [[ "$OSTYPE" == darwin* ]]; then
+    run_cmd sudo shutdown -h now
+  elif [[ "$OSTYPE" == msys* || "$OSTYPE" == win32 ]]; then
+    run_cmd shutdown /s /t 0 /f
+  else
+    log "Unsupported OSTYPE for automated shutdown: $OSTYPE"
+  fi
+}
+
+main() {
+  parse_args "$@"
+  check_dependencies
+
+  log "Emergency shutdown initiated."
+  log "Log file: $LOG_FILE"
+
+  if ! $CONFIRMED; then
+    confirm
+  fi
+
+  audit_state
+  azure_shutdown
+  aws_shutdown
+  revoke_credentials
+  network_isolation_local
+
+  log "Cloud systems halted."
+  local_shutdown
+  log "Run completed."
+}
+
+main "$@"
diff --git a/cloud_security.py b/cloud_security.py
new file mode 100644
index 0000000000000000000000000000000000000000..66eb3d7e24278be270ed1e3eb7856e8717878e61
--- /dev/null
+++ b/cloud_security.py
@@ -0,0 +1,118 @@
+"""Cloud access protection and trusted-state restoration utilities.
+
+This module enforces two core controls:
+1) Prevent non-authorized or malevolent actors from accessing/changing cloud state.
+2) Automatically restore cloud state to the last trusted baseline when an outside
+   actor attempts a change.
+"""
+
+from __future__ import annotations
+
+from copy import deepcopy
+from dataclasses import dataclass, field
+from datetime import datetime
+from typing import Any, Dict, Iterable, List, MutableMapping, Optional
+
+
+@dataclass(frozen=True)
+class CloudActor:
+    """Represents a caller trying to access cloud data."""
+
+    actor_id: str
+    roles: List[str] = field(default_factory=list)
+    tags: List[str] = field(default_factory=list)
+    risk_score: float = 0.0
+
+
+@dataclass
+class CloudAccessPolicy:
+    """Allowlist policy for cloud access control."""
+
+    trusted_actor_ids: Iterable[str]
+    trusted_roles: Iterable[str] = field(default_factory=lambda: ["cloud_admin", "cloud_operator"])
+    blocked_tags: Iterable[str] = field(default_factory=lambda: ["malevolent", "suspended", "blocked"])
+    max_risk_score: float = 0.7
+
+    def is_authorized(self, actor: CloudActor) -> bool:
+        """True when the actor is trusted by ID or role and not blocked."""
+        if self.is_malevolent(actor):
+            return False
+
+        trusted_ids = set(self.trusted_actor_ids)
+        trusted_roles = {r.lower() for r in self.trusted_roles}
+        actor_roles = {r.lower() for r in actor.roles}
+
+        return actor.actor_id in trusted_ids or bool(actor_roles & trusted_roles)
+
+    def is_malevolent(self, actor: CloudActor) -> bool:
+        """Heuristic classifier for known-bad actors."""
+        blocked = {t.lower() for t in self.blocked_tags}
+        actor_tags = {t.lower() for t in actor.tags}
+
+        return actor.risk_score > self.max_risk_score or bool(actor_tags & blocked)
+
+
+class CloudStateGuardian:
+    """Protect and restore cloud state using trusted baselines."""
+
+    def __init__(self, policy: CloudAccessPolicy):
+        self.policy = policy
+        self._trusted_baseline: Dict[str, Any] = {}
+        self.audit_log: List[Dict[str, Any]] = []
+
+    def snapshot_trusted_baseline(self, state: MutableMapping[str, Any], actor: CloudActor) -> Dict[str, Any]:
+        """Record a trusted baseline snapshot; only authorized actors may do this."""
+        self._require_authorized(actor, operation="snapshot_baseline")
+
+        self._trusted_baseline = deepcopy(dict(state))
+        event = self._event(actor, "snapshot_baseline", allowed=True)
+        self.audit_log.append(event)
+        return event
+
+    def update_state(self, state: MutableMapping[str, Any], updates: Dict[str, Any], actor: CloudActor) -> Dict[str, Any]:
+        """Apply updates if authorized, otherwise rollback to trusted baseline."""
+        if self.policy.is_authorized(actor):
+            state.update(deepcopy(updates))
+            event = self._event(actor, "update_state", allowed=True, extra={"keys": sorted(updates.keys())})
+            self.audit_log.append(event)
+            return event
+
+        restored = self.restore_untrusted_changes(state, actor)
+        event = self._event(
+            actor,
+            "update_state",
+            allowed=False,
+            extra={
+                "reason": "unauthorized_or_malevolent",
+                "restored": restored,
+                "keys_attempted": sorted(updates.keys()),
+            },
+        )
+        self.audit_log.append(event)
+        return event
+
+    def restore_untrusted_changes(self, state: MutableMapping[str, Any], actor: CloudActor) -> bool:
+        """Restore full cloud state to last trusted baseline for outside actors."""
+        if self.policy.is_authorized(actor):
+            return False
+
+        state.clear()
+        state.update(deepcopy(self._trusted_baseline))
+        self.audit_log.append(self._event(actor, "restore_untrusted_changes", allowed=True))
+        return True
+
+    def _require_authorized(self, actor: CloudActor, operation: str) -> None:
+        if not self.policy.is_authorized(actor):
+            raise PermissionError(f"{operation} denied for actor {actor.actor_id}")
+
+    @staticmethod
+    def _event(actor: CloudActor, action: str, allowed: bool, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
+        payload = {
+            "timestamp": datetime.now().isoformat(),
+            "actor_id": actor.actor_id,
+            "action": action,
+            "allowed": allowed,
+        }
+        if extra:
+            payload.update(extra)
+        return payload
diff --git a/README.md b/README.md
index 4d7ccaa8ce6e61c69d6948882582873badef63da..81a0443a1bccb3d3490b933401c141feabe4dab1 100644
--- a/README.md
+++ b/README.md
@@ -344724,26 +344724,50 @@ class MetaphysicalPractitioner:
 
         # Check if capability is enabled
         if not capability.is_usable:
             return False, "Capability is disabled."
 
         # Check energy
         energy_cost = capability.base_power_level * 0.5
         if self.energy_pool < energy_cost:
             return False, f"Insufficient energy. Need {energy_cost:.1f}, have {self.energy_pool:.1f}"
 
         # Check consciousness
         if self.consciousness_level < 0.5:
             return False, "Consciousness level too low to maintain metaphysical connection."
 
         # Check all philosophical frameworks
         for framework in self.philosophical_frameworks:
             if not framework.evaluate_restriction(capability):
                 return False, f"Violates {type(framework).__name__}: {framework.get_restriction_reason()}"
 
         return True, "Capability can be used."
 
     def use_capability(self, capability: MetaphysicalCapability) -> Dict:
         """Attempt to use a capability. Returns result details."""
         can_use, reason = self.can_use_capability(capability)
         
-        result = {
\ No newline at end of file
+        result = {
+## Cloud Protection Extension
+
+To support cloud hardening against malevolent/outside users, see `cloud_security.py`:
+
+- `CloudAccessPolicy` keeps an allow-list of users who may modify cloud state.
+- `CloudStateProtector.apply_change(...)` only applies updates for authorized users.
+- Unauthorized updates are blocked and returned as `rolled_back` with the trusted state restored.
+- `recover_from_external_state(...)` compares observed external state and returns the trusted snapshot for restoration workflows.
+- `audit_log` records all attempts for incident response.
+
+Quick example:
+
+```python
+from cloud_security import CloudAccessPolicy, CloudStateProtector
+
+policy = CloudAccessPolicy(allowed_users={"admin", "secops"})
+protector = CloudStateProtector(
+    initial_state={"bucket_public": False, "versioning": True},
+    access_policy=policy,
+)
+
+protector.apply_change("admin", {"bucket_public": False})       # applied
+protector.apply_change("outsider", {"bucket_public": True})      # rolled_back
+```
diff --git a/cloud_security.py b/cloud_security.py
new file mode 100644
index 0000000000000000000000000000000000000000..291d042ebae027b65550842ef6a32daddfb19d68
--- /dev/null
+++ b/cloud_security.py
@@ -0,0 +1,139 @@
+"""Cloud access control and unauthorized-change restoration utilities."""
+
+from __future__ import annotations
+
+from copy import deepcopy
+from dataclasses import dataclass
+from datetime import datetime
+from typing import Any, Dict, List, Optional, Set
+
+
+@dataclass
+class CloudChange:
+    """Represents a single cloud state mutation."""
+
+    timestamp: str
+    actor_id: str
+    key: str
+    old_value: Any
+    new_value: Any
+    authorized: bool
+
+
+class CloudAccessManager:
+    """Manage cloud access and automatically restore unauthorized changes.
+
+    Design goals:
+    - Only authorized users can make durable changes.
+    - Every mutation is logged with actor + authorization status.
+    - Any changes made by outside users can be reverted by replaying authorized history.
+    """
+
+    def __init__(self, initial_state: Optional[Dict[str, Any]] = None, authorized_users: Optional[Set[str]] = None):
+        self._baseline_state: Dict[str, Any] = deepcopy(initial_state or {})
+        self._state: Dict[str, Any] = deepcopy(self._baseline_state)
+        self._authorized_users: Set[str] = set(authorized_users or set())
+        self._change_history: List[CloudChange] = []
+
+    @property
+    def state(self) -> Dict[str, Any]:
+        """Current cloud state snapshot."""
+        return deepcopy(self._state)
+
+    @property
+    def authorized_users(self) -> Set[str]:
+        """Read-only view of currently authorized user IDs."""
+        return set(self._authorized_users)
+
+    def grant_access(self, user_id: str) -> None:
+        """Grant cloud access to a user."""
+        self._authorized_users.add(user_id)
+
+    def revoke_access(self, user_id: str) -> None:
+        """Revoke cloud access from a user."""
+        self._authorized_users.discard(user_id)
+
+    def can_access(self, user_id: str) -> bool:
+        """Check whether a user is currently authorized."""
+        return user_id in self._authorized_users
+
+    def apply_change(self, actor_id: str, key: str, value: Any) -> Dict[str, Any]:
+        """Apply a state change and log whether actor was authorized.
+
+        Unauthorized changes are temporarily written, then can be fully restored
+        with ``restore_outside_changes``.
+        """
+        old_value = deepcopy(self._state.get(key))
+        authorized = self.can_access(actor_id)
+
+        self._state[key] = deepcopy(value)
+        entry = CloudChange(
+            timestamp=datetime.now().isoformat(),
+            actor_id=actor_id,
+            key=key,
+            old_value=old_value,
+            new_value=deepcopy(value),
+            authorized=authorized,
+        )
+        self._change_history.append(entry)
+
+        return {
+            "success": authorized,
+            "actor_id": actor_id,
+            "authorized": authorized,
+            "key": key,
+            "message": "change accepted" if authorized else "change flagged as unauthorized",
+            "timestamp": entry.timestamp,
+        }
+
+    def checkpoint(self) -> Dict[str, Any]:
+        """Promote current state to baseline after trusted review."""
+        self._baseline_state = deepcopy(self._state)
+        return {
+            "action": "checkpoint",
+            "timestamp": datetime.now().isoformat(),
+            "baseline_keys": sorted(self._baseline_state.keys()),
+        }
+
+    def restore_outside_changes(self) -> Dict[str, Any]:
+        """Restore state by removing all changes made by outside users.
+
+        Rebuilds the cloud state from baseline + authorized changes only.
+        """
+        rebuilt = deepcopy(self._baseline_state)
+        reverted: List[Dict[str, Any]] = []
+
+        for entry in self._change_history:
+            if entry.authorized:
+                rebuilt[entry.key] = deepcopy(entry.new_value)
+            else:
+                reverted.append(
+                    {
+                        "actor_id": entry.actor_id,
+                        "key": entry.key,
+                        "attempted_value": deepcopy(entry.new_value),
+                        "timestamp": entry.timestamp,
+                    }
+                )
+
+        self._state = rebuilt
+        return {
+            "action": "restore_outside_changes",
+            "reverted_count": len(reverted),
+            "reverted": reverted,
+            "timestamp": datetime.now().isoformat(),
+        }
+
+    def get_change_history(self) -> List[Dict[str, Any]]:
+        """Return all cloud mutations as serializable dictionaries."""
+        return [
+            {
+                "timestamp": e.timestamp,
+                "actor_id": e.actor_id,
+                "key": e.key,
+                "old_value": deepcopy(e.old_value),
+                "new_value": deepcopy(e.new_value),
+                "authorized": e.authorized,
+            }
+            for e in self._change_history
+        ]
diff --git a/authorized_directory/system_network_note.json b/authorized_directory/system_network_note.json
new file mode 100644
index 0000000000000000000000000000000000000000..111a133f3e468380652fa7841025af2fb7c976f1
--- /dev/null
+++ b/authorized_directory/system_network_note.json
@@ -0,0 +1,7 @@
+{
+  "event": "authorized_directory_noted",
+  "network": "Cloud computational network",
+  "directory": "/workspace/Prev_NW/authorized_directory",
+  "message": "Cloud computational network: authorized directory recorded within system.",
+  "timestamp_utc": "2026-02-28T17:25:38.855932+00:00"
+}
diff --git a/cloud_network_note.py b/cloud_network_note.py
new file mode 100644
index 0000000000000000000000000000000000000000..aa606a4347b95e07e4a37d547040c4c2dc76c620
--- /dev/null
+++ b/cloud_network_note.py
@@ -0,0 +1,65 @@
+"""Record a cloud computational network authorization note in a directory.
+
+Usage:
+    python cloud_network_note.py /path/to/authorized_dir --network "Cloud computational network"
+"""
+
+from __future__ import annotations
+
+import argparse
+import json
+from datetime import datetime, timezone
+from pathlib import Path
+
+
+def build_note(network_name: str, directory: Path) -> dict:
+    """Create a structured note payload for audit/logging."""
+    return {
+        "event": "authorized_directory_noted",
+        "network": network_name,
+        "directory": str(directory.resolve()),
+        "message": f"{network_name}: authorized directory recorded within system.",
+        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
+    }
+
+
+def write_note(directory: Path, network_name: str, filename: str = "system_network_note.json") -> Path:
+    """Write a JSON note into the specified directory."""
+    directory.mkdir(parents=True, exist_ok=True)
+    note_path = directory / filename
+
+    payload = build_note(network_name=network_name, directory=directory)
+    note_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
+    return note_path
+
+
+def parse_args() -> argparse.Namespace:
+    parser = argparse.ArgumentParser(
+        description="Record that a cloud computational network directory is authorized."
+    )
+    parser.add_argument("directory", type=Path, help="Target authorized directory.")
+    parser.add_argument(
+        "--network",
+        default="Cloud computational network",
+        help="Network name to record in the note.",
+    )
+    parser.add_argument(
+        "--filename",
+        default="system_network_note.json",
+        help="Name of the note file to create inside the directory.",
+    )
+    return parser.parse_args()
+
+
+def main() -> None:
+    args = parse_args()
+    note_path = write_note(
+        directory=args.directory,
+        network_name=args.network,
+        filename=args.filename,
+    )
+    print(f"Authorization note written to: {note_path}")
+
+
+if __name__ == "__main__":
+    main()
diff --git a/authorized_directory_notifier.py b/authorized_directory_notifier.py
new file mode 100644
index 0000000000000000000000000000000000000000..2caa0d631b5fff3e88a9c69fdcb4febd837540d3
--- /dev/null
+++ b/authorized_directory_notifier.py
@@ -0,0 +1,85 @@
+"""Utility to note authorized cloud-compute directories in local system records."""
+
+from __future__ import annotations
+
+import argparse
+import json
+from datetime import datetime, timezone
+from pathlib import Path
+
+
+
+def note_authorized_directory(
+    network_name: str,
+    authorized_directory: str,
+    output_file: str = "system_authorization_notes.json",
+    message: str = "Cloud computational network authorized directory recorded.",
+) -> dict:
+    """Append an authorization note to a local JSON log file."""
+    directory = Path(authorized_directory).expanduser().resolve()
+    output_path = Path(output_file).expanduser().resolve()
+
+    note = {
+        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
+        "network": network_name,
+        "authorized_directory": str(directory),
+        "message": message,
+    }
+
+    if output_path.exists():
+        with output_path.open("r", encoding="utf-8") as f:
+            data = json.load(f)
+            if not isinstance(data, list):
+                raise ValueError("Output file exists but does not contain a JSON list.")
+    else:
+        data = []
+
+    data.append(note)
+
+    with output_path.open("w", encoding="utf-8") as f:
+        json.dump(data, f, indent=2)
+
+    return note
+
+
+
+def _build_parser() -> argparse.ArgumentParser:
+    parser = argparse.ArgumentParser(
+        description="Record an authorized directory for a cloud computational network."
+    )
+    parser.add_argument("network_name", help="Name of the cloud computational network")
+    parser.add_argument(
+        "authorized_directory",
+        help="Authorized directory path to record",
+    )
+    parser.add_argument(
+        "--output-file",
+        default="system_authorization_notes.json",
+        help="Path to the JSON note log file (default: system_authorization_notes.json)",
+    )
+    parser.add_argument(
+        "--message",
+        default="Cloud computational network authorized directory recorded.",
+        help="Optional custom message to store with the note",
+    )
+    return parser
+
+
+
+def main() -> None:
+    parser = _build_parser()
+    args = parser.parse_args()
+
+    note = note_authorized_directory(
+        network_name=args.network_name,
+        authorized_directory=args.authorized_directory,
+        output_file=args.output_file,
+        message=args.message,
+    )
+
+    print("Authorization note recorded:")
+    print(json.dumps(note, indent=2))
+
+
+if __name__ == "__main__":
+    main()
diff --git a/CLOUD_IMPACT_AUDIT.md b/CLOUD_IMPACT_AUDIT.md
new file mode 100644
index 0000000000000000000000000000000000000000..ab8244230534aa0cfeb9a76280a16ad3eda9a4e7
--- /dev/null
+++ b/CLOUD_IMPACT_AUDIT.md
@@ -0,0 +1,42 @@
+# Cloud Impact Audit (Repo: Prev_NW)
+
+## Quick answer
+Yes — this repository contains items that could negatively affect cloud safety, cost, or operations if executed as-is. The most beneficial immediate action is to **quarantine/remove nonessential operational scripts and patch-dump files**, and enforce a strict execution policy.
+
+## High-risk items to quarantine or remove
+
+1. **`more codes to restore random`**
+   - Contains Azure control-plane inventory/lockdown automation logic.
+   - Even with safety flags, this script can directly affect cloud resources if toggles are changed.
+   - Recommendation: move to `quarantine/` or remove unless intentionally maintained with review.
+
+2. **`metadata_reset.py` Git reset helpers**
+   - Includes commands like `git checkout -- .`, `git reset --hard HEAD`, and `git rm -r --cached .`.
+   - In CI/CD or shared automation contexts, this can wipe staged/uncommitted work and destabilize deployments.
+   - Recommendation: keep only if needed, gate behind explicit environment flag + dry-run mode.
+
+3. **Patch-dump artifacts with executable-looking payloads**
+   - Files such as `telemet.try`, `gov.prg`, `Electron`, `Pyramid`, `po.`, `j.pg`, and `spectral.analysis` appear to be diff payloads rather than stable source files.
+   - They increase confusion and accidental execution/import risk.
+   - Recommendation: archive outside the main branch, or move to `docs/archive/patches/` with clear `*.patch` naming.
+
+4. **Unpinned install instruction in `me`**
+   - `pip install numpy sounddevice soundfile` is unpinned.
+   - Unpinned dependencies can create supply-chain drift and reproducibility failures.
+   - Recommendation: replace with pinned versions in `requirements.txt` or `constraints.txt`.
+
+## Low-risk / maintenance improvements
+
+- Add a repository policy:
+  - No direct control-plane scripts in root directory.
+  - No unpinned install commands in tracked files.
+  - All operational scripts must support `--dry-run` and explicit confirmation.
+- Add pre-commit checks to block dangerous patterns (`reset --hard`, `rm -r --cached`, direct cloud-wide mutations).
+
+## Suggested immediate triage plan
+
+1. Quarantine high-risk/unclear root files.
+2. Add dependency pinning.
+3. Add CI lint for dangerous command patterns.
+4. Require code-owner review for any cloud-operation script.
+
diff --git a/CLOUD_IMPACT_ASSESSMENT.md b/CLOUD_IMPACT_ASSESSMENT.md
new file mode 100644
index 0000000000000000000000000000000000000000..6941e1196303458f2ddb82439be1743a5b91d1e2
--- /dev/null
+++ b/CLOUD_IMPACT_ASSESSMENT.md
@@ -0,0 +1,40 @@
+# Cloud Impact Assessment
+
+This repository contains several mixed-purpose scripts. The items below focus on what is likely to **help** cloud reliability/cost control versus what may **negatively affect** cloud resources.
+
+## What would benefit the cloud
+
+- Keep and standardize the temporary scaling ideas in `system.boost.azure`, but only the guarded/ephemeral parts (time-boxed scaling up then restoring).
+- Keep process-scoped telemetry controls from `telemet.try` (the `telemetry_restriction.py` patch content) because they reduce unnecessary outbound telemetry noise in controlled runs.
+- Keep reset/maintenance utilities in `metadata_reset.py` that help recover deterministic state and snapshots.
+
+## Modules/scripts that should be removed or split out
+
+- `system.boost.azure` currently mixes:
+  - safe optimization/scaling snippets,
+  - deployment orchestration,
+  - and **resource-deletion cleaners** (disk/NIC/NSG deletion logic).
+
+  Recommended action:
+  1. Move deletion cleaners into a separately named admin-only script.
+  2. Require explicit environment gating (for example `ALLOW_DESTRUCTIVE=1`) and confirmation checks.
+  3. Keep the default path non-destructive (`--dry-run`).
+
+- `telemet.try` appears to contain multiple diff payloads and duplicate patch-like content in one file. This should be converted into a single executable module (`telemetry_restriction.py`) and a short README with usage examples.
+
+## Installations/config changes that can negatively affect cloud
+
+- Any script that performs broad `az ... delete` operations without strict scoping, approval gates, and tags may remove active dependencies.
+- Interactive scripts that prompt during CI/CD can cause partial deployments and inconsistent state.
+- Mixed-language monolithic files (PowerShell + Bash + C# snippets in one file) increase operational risk and accidental execution of the wrong section.
+
+## Recommended next cleanup
+
+1. Extract `system.boost.azure` into:
+   - `azure_boost_safe.ps1` (scale/optimize only)
+   - `azure_cleanup_destructive.ps1` (manual-only destructive tasks)
+2. Add a minimal policy:
+   - destructive tasks disabled by default,
+   - mandatory dry-run first,
+   - required resource-group and tag filter.
+3. Normalize telemetry utility into one Python file and add tests for policy parsing.
diff --git a/CLOUD_IMPACT_AUDIT.md b/CLOUD_IMPACT_AUDIT.md
new file mode 100644
index 0000000000000000000000000000000000000000..ab8244230534aa0cfeb9a76280a16ad3eda9a4e7
--- /dev/null
+++ b/CLOUD_IMPACT_AUDIT.md
@@ -0,0 +1,42 @@
+# Cloud Impact Audit (Repo: Prev_NW)
+
+## Quick answer
+Yes — this repository contains items that could negatively affect cloud safety, cost, or operations if executed as-is. The most beneficial immediate action is to **quarantine/remove nonessential operational scripts and patch-dump files**, and enforce a strict execution policy.
+
+## High-risk items to quarantine or remove
+
+1. **`more codes to restore random`**
+   - Contains Azure control-plane inventory/lockdown automation logic.
+   - Even with safety flags, this script can directly affect cloud resources if toggles are changed.
+   - Recommendation: move to `quarantine/` or remove unless intentionally maintained with review.
+
+2. **`metadata_reset.py` Git reset helpers**
+   - Includes commands like `git checkout -- .`, `git reset --hard HEAD`, and `git rm -r --cached .`.
+   - In CI/CD or shared automation contexts, this can wipe staged/uncommitted work and destabilize deployments.
+   - Recommendation: keep only if needed, gate behind explicit environment flag + dry-run mode.
+
+3. **Patch-dump artifacts with executable-looking payloads**
+   - Files such as `telemet.try`, `gov.prg`, `Electron`, `Pyramid`, `po.`, `j.pg`, and `spectral.analysis` appear to be diff payloads rather than stable source files.
+   - They increase confusion and accidental execution/import risk.
+   - Recommendation: archive outside the main branch, or move to `docs/archive/patches/` with clear `*.patch` naming.
+
+4. **Unpinned install instruction in `me`**
+   - `pip install numpy sounddevice soundfile` is unpinned.
+   - Unpinned dependencies can create supply-chain drift and reproducibility failures.
+   - Recommendation: replace with pinned versions in `requirements.txt` or `constraints.txt`.
+
+## Low-risk / maintenance improvements
+
+- Add a repository policy:
+  - No direct control-plane scripts in root directory.
+  - No unpinned install commands in tracked files.
+  - All operational scripts must support `--dry-run` and explicit confirmation.
+- Add pre-commit checks to block dangerous patterns (`reset --hard`, `rm -r --cached`, direct cloud-wide mutations).
+
+## Suggested immediate triage plan
+
+1. Quarantine high-risk/unclear root files.
+2. Add dependency pinning.
+3. Add CI lint for dangerous command patterns.
+4. Require code-owner review for any cloud-operation script.
+
diff --git a/CLOUD_HYGIENE.md b/CLOUD_HYGIENE.md
new file mode 100644
index 0000000000000000000000000000000000000000..79f041790e97ff305c73d964cb735b428962b2cf
--- /dev/null
+++ b/CLOUD_HYGIENE.md
@@ -0,0 +1,34 @@
+# Cloud Hygiene Recommendations
+
+This repository has several cleanup opportunities that can improve cloud build speed, deployment reliability, and storage cost.
+
+## High-impact changes
+
+1. **Move oversized docs out of deployment context**
+   - `README.md` is ~10.7 MiB and will slow CI clone and artifact packaging.
+   - Consider splitting into smaller docs and keeping operational docs under ~1 MiB each.
+
+2. **Store media in object storage instead of git**
+   - `sounds.mp3` should be hosted in cloud object storage (S3/Azure Blob/GCS) and referenced by URL.
+   - Keep source repos code-centric to reduce checkout time and runner disk usage.
+
+3. **Rename non-portable filenames**
+   - Files containing spaces/special chars are brittle in cloud scripts and cross-platform runners.
+   - Rename these:
+     - `Issues:)`
+     - `ke;;y.jen`
+     - `more codes to restore random`
+
+## Module/dependency impact
+
+- Current Python files import only stdlib modules (plus local modules), so there are **no third-party installs currently required**.
+- This is good for cloud cold-start and CI setup time.
+
+## Suggested next actions
+
+- Run `python tools/cloud_hygiene_audit.py` in CI and fail builds on:
+  - files larger than 5 MiB,
+  - non-portable names,
+  - checked-in media/binary assets.
+- Add `.gitattributes` or repo policy for large artifacts (or Git LFS if absolutely necessary).
+- Add a lightweight packaging whitelist so deployments include only runtime files.
diff --git a/tools/cloud_hygiene_audit.py b/tools/cloud_hygiene_audit.py
new file mode 100644
index 0000000000000000000000000000000000000000..241c95114a204e630361c2aa463f3933f76c112e
--- /dev/null
+++ b/tools/cloud_hygiene_audit.py
@@ -0,0 +1,122 @@
+#!/usr/bin/env python3
+"""Basic cloud hygiene audit for this repository.
+
+Highlights files and naming patterns that commonly hurt cloud deployments:
+- very large files in source control
+- binary/media artifacts that usually belong in object storage
+- non-portable file names (spaces / special characters)
+"""
+
+from __future__ import annotations
+
+import argparse
+import json
+import re
+from pathlib import Path
+
+BINARY_EXTENSIONS = {
+    ".mp3",
+    ".jpg",
+    ".jpeg",
+    ".png",
+    ".gif",
+    ".zip",
+    ".tar",
+    ".gz",
+    ".exe",
+    ".dll",
+    ".so",
+    ".dylib",
+    ".pdf",
+}
+
+NON_PORTABLE_CHARS = re.compile(r"[^A-Za-z0-9._/-]")
+
+
+def to_kib(size: int) -> float:
+    return size / 1024
+
+
+def collect_repo_files(root: Path) -> list[Path]:
+    return [p for p in root.rglob("*") if p.is_file() and ".git" not in p.parts]
+
+
+def audit(root: Path, large_file_threshold_kib: int) -> dict:
+    files = collect_repo_files(root)
+
+    large_files = []
+    binary_like = []
+    non_portable_names = []
+
+    for file_path in files:
+        rel = file_path.relative_to(root)
+        stat = file_path.stat()
+        size_kib = to_kib(stat.st_size)
+
+        if size_kib >= large_file_threshold_kib:
+            large_files.append({"path": str(rel), "size_kib": round(size_kib, 1)})
+
+        if file_path.suffix.lower() in BINARY_EXTENSIONS:
+            binary_like.append({"path": str(rel), "size_kib": round(size_kib, 1)})
+
+        if NON_PORTABLE_CHARS.search(str(rel)):
+            non_portable_names.append(str(rel))
+
+    return {
+        "summary": {
+            "total_files": len(files),
+            "large_file_threshold_kib": large_file_threshold_kib,
+        },
+        "large_files": sorted(large_files, key=lambda x: x["size_kib"], reverse=True),
+        "binary_like_files": sorted(binary_like, key=lambda x: x["size_kib"], reverse=True),
+        "non_portable_names": sorted(non_portable_names),
+    }
+
+
+def main() -> None:
+    parser = argparse.ArgumentParser(description="Audit repository cloud hygiene concerns.")
+    parser.add_argument("--root", default=".", help="Repository root")
+    parser.add_argument(
+        "--large-file-threshold-kib",
+        type=int,
+        default=5120,
+        help="Threshold for flagging large files (default: 5120 KiB = 5 MiB)",
+    )
+    parser.add_argument("--json", action="store_true", help="Output JSON")
+
+    args = parser.parse_args()
+    report = audit(Path(args.root).resolve(), args.large_file_threshold_kib)
+
+    if args.json:
+        print(json.dumps(report, indent=2))
+        return
+
+    print("Cloud Hygiene Audit")
+    print("===================")
+    print(f"Total files scanned: {report['summary']['total_files']}")
+    print(f"Large-file threshold: {report['summary']['large_file_threshold_kib']} KiB")
+
+    print("\nLarge files:")
+    if report["large_files"]:
+        for entry in report["large_files"]:
+            print(f" - {entry['path']}: {entry['size_kib']} KiB")
+    else:
+        print(" - none")
+
+    print("\nBinary/media-like files:")
+    if report["binary_like_files"]:
+        for entry in report["binary_like_files"]:
+            print(f" - {entry['path']}: {entry['size_kib']} KiB")
+    else:
+        print(" - none")
+
+    print("\nNon-portable file names:")
+    if report["non_portable_names"]:
+        for path in report["non_portable_names"]:
+            print(f" - {path}")
+    else:
+        print(" - none")
+
+
+if __name__ == "__main__":
+    main()
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Cloud Benevolence Engine</title>

<style>
:root {
  --bg: #0f172a;
  --good: #22c55e;
  --warn: #facc15;
  --bad: #ef4444;
  --accent: #38bdf8;
  --text: #e2e8f0;
}

body {
  background: var(--bg);
  color: var(--text);
  font-family: Consolas, monospace;
  padding: 30px;
}

h1 {
  color: var(--accent);
}

.log {
  background: #1e293b;
  padding: 15px;
  border-radius: 8px;
  margin-top: 20px;
  max-height: 300px;
  overflow-y: auto;
}

.bad { color: var(--bad); }
.good { color: var(--good); }
.warn { color: var(--warn); }

button {
  padding: 10px 16px;
  margin-top: 15px;
  border: none;
  border-radius: 6px;
  background: var(--accent);
  color: black;
  cursor: pointer;
}

button:hover {
  background: var(--good);
}
</style>
</head>

<body>

<h1>🌤 Cloud Benevolence Rewriter</h1>
<p>Detecting and transforming insecure cloud changes into benevolent configurations.</p>

<button onclick="runEngine()">Scan & Rewrite</button>

<div class="log" id="log"></div>

<script>
const insecurePatterns = [
  { issue: "Public S3 Bucket", fix: "Block Public Access Enabled" },
  { issue: "Open Port 0.0.0.0/0", fix: "Restricted CIDR Applied" },
  { issue: "Disabled MFA", fix: "MFA Enforcement Enabled" },
  { issue: "Unencrypted Storage", fix: "Encryption Enabled" }
];

function log(message, type) {
  const logDiv = document.getElementById("log");
  const entry = document.createElement("div");
  entry.className = type;
  entry.textContent = message;
  logDiv.appendChild(entry);
}

function runEngine() {
  log("Scanning cloud configuration...", "warn");

  setTimeout(() => {
    insecurePatterns.forEach(pattern => {
      log("Detected: " + pattern.issue, "bad");

      setTimeout(() => {
        log("Rewritten to: " + pattern.fix, "good");
      }, 800);
    });

    setTimeout(() => {
      log("Cloud posture restored to benevolent baseline.", "good");
    }, 2000);

  }, 1000);
}
</script>

</body>
</html>
// quarantine_high_risk.js
// SAFE VERSION — Quarantines HIGH risk identities instead of deleting.

const { execSync } = require("child_process");

const DRY_RUN = process.argv.includes("--dry-run");

const HIGH_RISK_THRESHOLD = 85;

// Example flagged profiles input
const flaggedProfiles = [
  { id: "aws:user/LegacyAdmin", provider: "aws", risk: 92, type: "user", name: "LegacyAdmin" },
  { id: "aws:role/DeployBot", provider: "aws", risk: 88, type: "role", name: "DeployBot" },
  { id: "azure:user/devops@contoso", provider: "azure", risk: 90, type: "user", name: "devops@contoso" }
];

function run(cmd) {
  if (DRY_RUN) {
    console.log("[DRY RUN]", cmd);
  } else {
    console.log("[EXEC]", cmd);
    execSync(cmd, { stdio: "inherit" });
  }
}

function quarantineAWS(profile) {
  console.log(`Quarantining AWS profile: ${profile.name}`);

  if (profile.type === "user") {
    run(`aws iam update-login-profile --user-name ${profile.name} --password-reset-required`);
    run(`aws iam attach-user-policy --user-name ${profile.name} --policy-arn arn:aws:iam::aws:policy/AWSDenyAll`);
  }

  if (profile.type === "role") {
    run(`aws iam attach-role-policy --role-name ${profile.name} --policy-arn arn:aws:iam::aws:policy/AWSDenyAll`);
  }
}

function quarantineAzure(profile) {
  console.log(`Quarantining Azure profile: ${profile.name}`);

  run(`az ad user update --id ${profile.name} --account-enabled false`);
}

function main() {
  console.log("=== HIGH RISK PROFILE QUARANTINE PREVIEW ===");

  flaggedProfiles.forEach(profile => {
    if (profile.risk >= HIGH_RISK_THRESHOLD) {
      console.log(`HIGH risk detected (${profile.risk}) → ${profile.id}`);

      if (profile.provider === "aws") {
        quarantineAWS(profile);
      }

      if (profile.provider === "azure") {
        quarantineAzure(profile);
      }
    }
  });

  console.log("=== OPERATION COMPLETE ===");
}

main();
node quarantine_high_risk.js --dry-run
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Cloud Drift Watch — Risky Profiles</title>

  <style>
    :root{
      --bg:#0b1220; --panel:#111b2e; --text:#e6edf7; --muted:#9fb0c8;
      --good:#22c55e; --warn:#fbbf24; --bad:#ef4444; --accent:#38bdf8;
      --border:#23324f;
    }
    body{
      margin:0; padding:24px; background:var(--bg); color:var(--text);
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    }
    h1{ margin:0 0 6px; color:var(--accent); font-size:22px; }
    .sub{ color:var(--muted); margin-bottom:18px; line-height:1.4; }
    .row{ display:flex; gap:12px; flex-wrap:wrap; align-items:center; }
    .card{
      background:var(--panel); border:1px solid var(--border);
      border-radius:12px; padding:14px; margin-top:14px;
    }
    input, select, button{
      background:#0f1830; color:var(--text); border:1px solid var(--border);
      padding:10px 10px; border-radius:10px; outline:none;
    }
    input{ min-width: 260px; }
    button{
      cursor:pointer; border-color:#2b3a5a;
    }
    button:hover{ border-color:var(--accent); }
    .pill{
      display:inline-flex; align-items:center; gap:8px;
      padding:6px 10px; border-radius:999px; border:1px solid var(--border);
      color:var(--muted);
    }
    .dot{ width:10px; height:10px; border-radius:50%; display:inline-block; }
    .dot.good{ background:var(--good); }
    .dot.warn{ background:var(--warn); }
    .dot.bad{ background:var(--bad); }

    table{
      width:100%; border-collapse:separate; border-spacing:0;
      overflow:hidden; border-radius:12px; border:1px solid var(--border);
      margin-top:12px;
    }
    thead th{
      text-align:left; padding:12px; background:#0f1830; color:var(--muted);
      border-bottom:1px solid var(--border); font-weight:600; font-size:12px;
    }
    tbody td{
      padding:12px; border-bottom:1px solid var(--border);
      vertical-align:top; font-size:13px;
    }
    tbody tr:hover{ background:#0e1730; }
    .sev{
      font-weight:700; letter-spacing:0.2px;
    }
    .sev.good{ color:var(--good); }
    .sev.warn{ color:var(--warn); }
    .sev.bad{ color:var(--bad); }

    .reason{ color:var(--muted); font-size:12px; margin-top:3px; }
    .mono{ color:var(--muted); font-size:12px; }
    .small{ font-size:12px; color:var(--muted); }
    .right{ margin-left:auto; }
    .footer-note{
      margin-top:12px; color:var(--muted); font-size:12px; line-height:1.4;
    }
    .log{
      max-height:220px; overflow:auto; margin-top:10px;
      background:#0f1830; border:1px solid var(--border);
      border-radius:12px; padding:10px;
      font-size:12px; color:var(--muted);
      white-space:pre-wrap;
    }
  </style>
</head>

<body>
  <h1>☁️ Cloud Drift Watch — Risky Profiles</h1>
  <div class="sub">
    Displays identities (users/roles/service principals) that appear to be introducing insecure drift.
    This page can run with demo data or fetch from <span class="mono">/api/risky-profiles</span> on your backend.
  </div>

  <div class="row card">
    <span class="pill"><span class="dot bad"></span> High</span>
    <span class="pill"><span class="dot warn"></span> Medium</span>
    <span class="pill"><span class="dot good"></span> Low</span>

    <div class="right row" style="gap:10px;">
      <input id="q" placeholder="Search: name, provider, action, reason…" />
      <select id="provider">
        <option value="all">All Clouds</option>
        <option value="aws">AWS</option>
        <option value="azure">Azure</option>
      </select>
      <select id="minRisk">
        <option value="0">Risk ≥ 0</option>
        <option value="40">Risk ≥ 40</option>
        <option value="70">Risk ≥ 70</option>
        <option value="85">Risk ≥ 85</option>
      </select>
      <select id="sortBy">
        <option value="risk_desc">Sort: Risk (high→low)</option>
        <option value="time_desc">Sort: Last Activity (new→old)</option>
        <option value="name_asc">Sort: Name (A→Z)</option>
      </select>
      <button id="refresh">Refresh</button>
      <button id="toggleMode" title="Switch between demo data and backend fetch">Use Backend: OFF</button>
    </div>
  </div>

  <div class="card">
    <div class="row">
      <div><strong>Profiles flagged</strong> <span class="small" id="count"></span></div>
      <div class="right small" id="lastUpdated"></div>
    </div>

    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Profile</th>
          <th>Cloud</th>
          <th>Risk</th>
          <th>Last risky change</th>
          <th>What changed</th>
          <th>Why flagged</th>
        </tr>
      </thead>
      <tbody id="rows"></tbody>
    </table>

    <div class="footer-note">
      Safe note: This dashboard is for <strong>your authorized accounts</strong>. It does not bypass controls.
      To power it with real data, feed it curated findings from AWS CloudTrail/Config/IAM Access Analyzer and Azure Activity Logs/Defender for Cloud/Entra ID.
    </div>
  </div>

  <div class="card">
    <div class="row">
      <strong>Audit stream</strong>
      <span class="right small">Local view; your backend should store immutable logs.</span>
    </div>
    <div class="log" id="audit"></div>
  </div>

<script>
(() => {
  // ----------------------------
  // Demo data (replace via backend)
  // ----------------------------
  const demo = [
    {
      id: "aws:role/DeployBot",
      name: "DeployBot",
      type: "role",
      provider: "aws",
      risk: 92,
      lastActivity: "2026-02-28T15:41:02Z",
      lastChange: "SecurityGroupIngress",
      changeDetail: "Added inbound rule: TCP 22 from 0.0.0.0/0",
      reason: "Exposed SSH to the internet (0.0.0.0/0).",
      recommendation: "Restrict CIDR to admin IPs or use SSM Session Manager; remove the rule."
    },
    {
      id: "azure:spn/App-CI",
      name: "App-CI",
      type: "servicePrincipal",
      provider: "azure",
      risk: 87,
      lastActivity: "2026-02-28T14:22:11Z",
      lastChange: "StorageAccountUpdate",
      changeDetail: "Enabled public blob access on storage account",
      reason: "Public blob access increases data exposure risk.",
      recommendation: "Disable public access; enforce private endpoints and Azure Policy."
    },
    {
      id: "aws:user/LegacyAdmin",
      name: "LegacyAdmin",
      type: "user",
      provider: "aws",
      risk: 78,
      lastActivity: "2026-02-28T12:05:44Z",
      lastChange: "AttachUserPolicy",
      changeDetail: "Attached AdministratorAccess",
      reason: "Privilege escalation / excessive permissions.",
      recommendation: "Replace with least-privilege role; require MFA; remove admin policy."
    },
    {
      id: "azure:user/devops@contoso",
      name: "devops@contoso",
      type: "user",
      provider: "azure",
      risk: 55,
      lastActivity: "2026-02-28T09:50:09Z",
      lastChange: "NSGRuleCreate",
      changeDetail: "Created inbound allow rule for 3389 (RDP) from broad IP range",
      reason: "RDP exposure increases brute-force risk.",
      recommendation: "Use Bastion/JIT; restrict source IP; require MFA + Conditional Access."
    },
    {
      id: "aws:role/ReadOnlyAnalytics",
      name: "ReadOnlyAnalytics",
      type: "role",
      provider: "aws",
      risk: 28,
      lastActivity: "2026-02-27T22:10:00Z",
      lastChange: "S3PutBucketPolicy",
      changeDetail: "Attempted bucket policy change (denied by SCP)",
      reason: "Attempted risky change but blocked (good guardrails).",
      recommendation: "Review intent; keep SCP/guardrails in place."
    },
  ];

  // ----------------------------
  // State
  // ----------------------------
  let useBackend = false;
  let data = [...demo];

  // ----------------------------
  // Utilities
  // ----------------------------
  const $ = (id) => document.getElementById(id);

  function sevClass(risk){
    if (risk >= 85) return "bad";
    if (risk >= 60) return "warn";
    return "good";
  }
  function sevLabel(risk){
    if (risk >= 85) return "HIGH";
    if (risk >= 60) return "MED";
    return "LOW";
  }
  function fmtTime(iso){
    try {
      const d = new Date(iso);
      return d.toLocaleString(undefined, { year:"numeric", month:"short", day:"2-digit", hour:"2-digit", minute:"2-digit" });
    } catch { return iso; }
  }
  function logAudit(msg){
    const line = `[${new Date().toISOString()}] ${msg}\n`;
    $("audit").textContent += line;
    $("audit").scrollTop = $("audit").scrollHeight;
  }

  // ----------------------------
  // Backend fetch (optional)
  // Your backend should return: { profiles: [...] } matching the demo schema
  // ----------------------------
  async function fetchBackend(){
    const res = await fetch("/api/risky-profiles", { method: "GET", headers: { "Accept":"application/json" } });
    if (!res.ok) throw new Error(`Backend returned ${res.status}`);
    const json = await res.json();
    if (!json || !Array.isArray(json.profiles)) throw new Error("Invalid backend payload");
    return json.profiles;
  }

  // ----------------------------
  // Render
  // ----------------------------
  function render(){
    const q = $("q").value.trim().toLowerCase();
    const provider = $("provider").value;
    const minRisk = Number($("minRisk").value);
    const sortBy = $("sortBy").value;

    let filtered = data.filter(p => {
      const hay = `${p.name} ${p.id} ${p.provider} ${p.type} ${p.lastChange} ${p.changeDetail} ${p.reason}`.toLowerCase();
      const matchQ = !q || hay.includes(q);
      const matchProvider = provider === "all" || p.provider === provider;
      const matchRisk = p.risk >= minRisk;
      return matchQ && matchProvider && matchRisk;
    });

    if (sortBy === "risk_desc") filtered.sort((a,b)=> b.risk - a.risk);
    if (sortBy === "time_desc") filtered.sort((a,b)=> new Date(b.lastActivity) - new Date(a.lastActivity));
    if (sortBy === "name_asc") filtered.sort((a,b)=> a.name.localeCompare(b.name));

    $("rows").innerHTML = filtered.map(p => {
      const s = sevClass(p.risk);
      return `
        <tr>
          <td class="sev ${s}">${sevLabel(p.risk)}</td>
          <td>
            <div><strong>${escapeHtml(p.name)}</strong> <span class="mono">(${escapeHtml(p.type)})</span></div>
            <div class="mono">${escapeHtml(p.id)}</div>
          </td>
          <td>${p.provider.toUpperCase()}</td>
          <td><strong>${p.risk}</strong></td>
          <td>${fmtTime(p.lastActivity)}</td>
          <td>
            <div><strong>${escapeHtml(p.lastChange)}</strong></div>
            <div class="reason">${escapeHtml(p.changeDetail)}</div>
          </td>
          <td>
            <div>${escapeHtml(p.reason)}</div>
            <div class="reason"><em>Suggested fix:</em> ${escapeHtml(p.recommendation)}</div>
          </td>
        </tr>
      `;
    }).join("");

    $("count").textContent = `(${filtered.length} shown / ${data.length} total)`;
    $("lastUpdated").textContent = `Updated: ${new Date().toLocaleString()}`;
  }

  // Basic HTML escape to avoid accidental injection from backend data
  function escapeHtml(str){
    return String(str)
      .replaceAll("&","&amp;")
      .replaceAll("<","&lt;")
      .replaceAll(">","&gt;")
      .replaceAll('"',"&quot;")
      .replaceAll("'","&#039;");
  }

  // ----------------------------
  // Events
  // ----------------------------
  ["q","provider","minRisk","sortBy"].forEach(id => $(id).addEventListener("input", render));

  $("toggleMode").addEventListener("click", () => {
    useBackend = !useBackend;
    $("toggleMode").textContent = `Use Backend: ${useBackend ? "ON" : "OFF"}`;
    logAudit(`Mode switched: ${useBackend ? "backend" : "demo"} data.`);
    render();
  });

  $("refresh").addEventListener("click", async () => {
    try{
      logAudit("Refresh requested.");
      if (useBackend){
        logAudit("Fetching /api/risky-profiles …");
        const profiles = await fetchBackend();
        data = profiles;
        logAudit(`Loaded ${profiles.length} profiles from backend.`);
      } else {
        data = [...demo];
        logAudit("Loaded demo dataset.");
      }
      render();
    } catch(e){
      logAudit(`ERROR: ${e.message}`);
      alert(`Could not refresh: ${e.message}`);
    }
  });

  // Initial render
  logAudit("Dashboard initialized.");
  render();
})();
</script>
</body>
</html>
// quarantine_high_risk.js
// SAFE VERSION — Quarantines HIGH risk identities instead of deleting.

const { execSync } = require("child_process");

const DRY_RUN = process.argv.includes("--dry-run");

const HIGH_RISK_THRESHOLD = 85;

// Example flagged profiles input
const flaggedProfiles = [
  { id: "aws:user/LegacyAdmin", provider: "aws", risk: 92, type: "user", name: "LegacyAdmin" },
  { id: "aws:role/DeployBot", provider: "aws", risk: 88, type: "role", name: "DeployBot" },
  { id: "azure:user/devops@contoso", provider: "azure", risk: 90, type: "user", name: "devops@contoso" }
];

function run(cmd) {
  if (DRY_RUN) {
    console.log("[DRY RUN]", cmd);
  } else {
    console.log("[EXEC]", cmd);
    execSync(cmd, { stdio: "inherit" });
  }
}

function quarantineAWS(profile) {
  console.log(`Quarantining AWS profile: ${profile.name}`);

  if (profile.type === "user") {
    run(`aws iam update-login-profile --user-name ${profile.name} --password-reset-required`);
    run(`aws iam attach-user-policy --user-name ${profile.name} --policy-arn arn:aws:iam::aws:policy/AWSDenyAll`);
  }

  if (profile.type === "role") {
    run(`aws iam attach-role-policy --role-name ${profile.name} --policy-arn arn:aws:iam::aws:policy/AWSDenyAll`);
  }
}

function quarantineAzure(profile) {
  console.log(`Quarantining Azure profile: ${profile.name}`);

  run(`az ad user update --id ${profile.name} --account-enabled false`);
}

function main() {
  console.log("=== HIGH RISK PROFILE QUARANTINE PREVIEW ===");

  flaggedProfiles.forEach(profile => {
    if (profile.risk >= HIGH_RISK_THRESHOLD) {
      console.log(`HIGH risk detected (${profile.risk}) → ${profile.id}`);

      if (profile.provider === "aws") {
        quarantineAWS(profile);
      }

      if (profile.provider === "azure") {
        quarantineAzure(profile);
      }
    }
  });

  console.log("=== OPERATION COMPLETE ===");
}

main();
POST /api/remediate
{
  profileId: "...",
  action: "restrict-policy"
}
POST /api/remediate
{
  profileId: "...",
  action: "restrict-policy"
}
pip install fastapi uvicorn
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from typing import List, Optional
import datetime

app = FastAPI(title="Cloud Risk Identity API")

ADMIN_TOKEN = "secure-admin-token"
HIGH_RISK_THRESHOLD = 85

class Profile(BaseModel):
    id: str
    provider: str
    risk: int
    last_action: str
    detail: str
    quarantined: bool = False

profiles = [
    Profile(
        id="aws:user/LegacyAdmin",
        provider="aws",
        risk=92,
        last_action="AttachUserPolicy",
        detail="Attached AdministratorAccess"
    ),
    Profile(
        id="azure:user/devops@tenant",
        provider="azure",
        risk=88,
        last_action="NSGRuleCreate",
        detail="Opened RDP to public internet"
    )
]

def validate_admin(token: str):
    if token != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Unauthorized")

@app.get("/profiles", response_model=List[Profile])
def get_profiles():
    return profiles

@app.get("/profiles/{profile_id}")
def get_profile(profile_id: str):
    for p in profiles:
        if p.id == profile_id:
            return p
    raise HTTPException(status_code=404, detail="Profile not found")

@app.put("/profiles/{profile_id}")
def alter_profile(profile_id: str, updated: Profile, x_admin_token: str = Header(...)):
    validate_admin(x_admin_token)
    for i, p in enumerate(profiles):
        if p.id == profile_id:
            profiles[i] = updated
            return {"message": "Profile updated"}
    raise HTTPException(status_code=404, detail="Profile not found")

@app.post("/profiles/{profile_id}/preview")
def preview_action(profile_id: str, x_admin_token: str = Header(...)):
    validate_admin(x_admin_token)

    for p in profiles:
        if p.id == profile_id:
            return {
                "mode": "preview",
                "actions": [
                    "Disable login",
                    "Revoke sessions",
                    "Remove elevated permissions"
                ],
                "timestamp": datetime.datetime.utcnow()
            }
    raise HTTPException(status_code=404, detail="Profile not found")

@app.post("/profiles/{profile_id}/execute")
def execute_action(profile_id: str, x_admin_token: str = Header(...)):
    validate_admin(x_admin_token)

    for p in profiles:
        if p.id == profile_id:
            if p.risk < HIGH_RISK_THRESHOLD:
                raise HTTPException(status_code=400, detail="Risk below threshold")

            p.quarantined = True

            return {
                "mode": "execute",
                "status": "Profile quarantined safely",
                "timestamp": datetime.datetime.utcnow()
            }

    raise HTTPException(status_code=404, detail="Profile not found")
uvicorn app:app --reload
uvicorn app:app --reload
npm init -y
npm install express body-parser
const express = require("express");
const bodyParser = require("body-parser");

const app = express();
app.use(bodyParser.json());

const ADMIN_TOKEN = "secure-admin-token";
const HIGH_RISK_THRESHOLD = 85;

let profiles = [
  {
    id: "aws:user/LegacyAdmin",
    provider: "aws",
    risk: 92,
    lastAction: "AttachUserPolicy",
    detail: "Attached AdministratorAccess",
    quarantined: false
  },
  {
    id: "azure:user/devops@tenant",
    provider: "azure",
    risk: 88,
    lastAction: "NSGRuleCreate",
    detail: "Opened RDP to public internet",
    quarantined: false
  }
];

function validateAdmin(req, res, next) {
  if (req.headers["x-admin-token"] !== ADMIN_TOKEN) {
    return res.status(403).json({ error: "Unauthorized" });
  }
  next();
}

app.get("/profiles", (req, res) => {
  res.json(profiles);
});

app.get("/profiles/:id", (req, res) => {
  const profile = profiles.find(p => p.id === req.params.id);
  if (!profile) return res.status(404).json({ error: "Not found" });
  res.json(profile);
});

app.put("/profiles/:id", validateAdmin, (req, res) => {
  const index = profiles.findIndex(p => p.id === req.params.id);
  if (index === -1) return res.status(404).json({ error: "Not found" });

  profiles[index] = req.body;
  res.json({ message: "Profile updated" });
});

app.post("/profiles/:id/preview", validateAdmin, (req, res) => {
  const profile = profiles.find(p => p.id === req.params.id);
  if (!profile) return res.status(404).json({ error: "Not found" });

  res.json({
    mode: "preview",
    actions: [
      "Disable login",
      "Revoke sessions",
      "Remove elevated permissions"
    ],
    timestamp: new Date()
  });
});

app.post("/profiles/:id/execute", validateAdmin, (req, res) => {
  const profile = profiles.find(p => p.id === req.params.id);
  if (!profile) return res.status(404).json({ error: "Not found" });

  if (profile.risk < HIGH_RISK_THRESHOLD) {
    return res.status(400).json({ error: "Risk below threshold" });
  }

  profile.quarantined = true;

  res.json({
    mode: "execute",
    status: "Profile quarantined safely",
    timestamp: new Date()
  });
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});
node server.js
node server.js
pip install fastapi uvicorn pydantic python-jose
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from typing import List
import datetime
import hashlib

app = FastAPI(title="Metaphysical Cloud Profile Examination Engine")

ADMIN_TOKEN = "secure-admin-token"
MFA_CODE = "123456"
HIGH_RISK_THRESHOLD = 85

class Identity(BaseModel):
    id: str
    provider: str
    privilege_level: int
    anomaly_score: int
    public_exposure: bool
    mfa_enabled: bool
    quarantined: bool = False

class AuditEntry(BaseModel):
    timestamp: datetime.datetime
    identity: str
    action: str
    preview: bool

identities = [
    Identity(
        id="aws:user/LegacyAdmin",
        provider="aws",
        privilege_level=95,
        anomaly_score=80,
        public_exposure=True,
        mfa_enabled=False
    ),
    Identity(
        id="azure:user/devops@tenant",
        provider="azure",
        privilege_level=85,
        anomaly_score=75,
        public_exposure=True,
        mfa_enabled=True
    )
]

audit_log: List[AuditEntry] = []

def validate_admin(token: str, mfa: str):
    if token != ADMIN_TOKEN or mfa != MFA_CODE:
        raise HTTPException(status_code=403, detail="Unauthorized")

def calculate_risk(identity: Identity):
    risk = (
        identity.privilege_level * 0.4 +
        identity.anomaly_score * 0.3 +
        (20 if identity.public_exposure else 0) +
        (15 if not identity.mfa_enabled else 0)
    )
    return int(min(risk, 100))

@app.get("/identities")
def list_identities():
    enriched = []
    for identity in identities:
        risk = calculate_risk(identity)
        enriched.append({
            "identity": identity,
            "risk": risk,
            "level": "HIGH" if risk >= HIGH_RISK_THRESHOLD else "MEDIUM"
        })
    return enriched

@app.post("/identities/{identity_id}/preview")
def preview(identity_id: str, x_admin_token: str = Header(...), x_mfa: str = Header(...)):
    validate_admin(x_admin_token, x_mfa)

    for identity in identities:
        if identity.id == identity_id:
            risk = calculate_risk(identity)
            actions = [
                "Disable login",
                "Revoke sessions",
                "Remove elevated roles",
                "Attach deny policy",
                "Enforce MFA"
            ]

            audit_log.append(AuditEntry(
                timestamp=datetime.datetime.utcnow(),
                identity=identity_id,
                action="preview",
                preview=True
            ))

            return {
                "mode": "preview",
                "risk": risk,
                "recommended_actions": actions
            }

    raise HTTPException(status_code=404, detail="Identity not found")

@app.post("/identities/{identity_id}/execute")
def execute(identity_id: str, x_admin_token: str = Header(...), x_mfa: str = Header(...)):
    validate_admin(x_admin_token, x_mfa)

    for identity in identities:
        if identity.id == identity_id:
            risk = calculate_risk(identity)

            if risk < HIGH_RISK_THRESHOLD:
                raise HTTPException(status_code=400, detail="Risk below HIGH threshold")

            identity.quarantined = True

            audit_log.append(AuditEntry(
                timestamp=datetime.datetime.utcnow(),
                identity=identity_id,
                action="quarantine",
                preview=False
            ))

            return {
                "status": "Identity quarantined safely",
                "risk": risk
            }

    raise HTTPException(status_code=404, detail="Identity not found")

@app.get("/audit")
def get_audit():
    return audit_log
uvicorn metaphysical_security:app --reload
npm init -y
npm install express body-parser
const express = require("express");
const bodyParser = require("body-parser");

const app = express();
app.use(bodyParser.json());

const ADMIN_TOKEN = "secure-admin-token";
const MFA_CODE = "123456";
const HIGH_RISK_THRESHOLD = 85;

let identities = [
  {
    id: "aws:user/LegacyAdmin",
    provider: "aws",
    privilegeLevel: 95,
    anomalyScore: 80,
    publicExposure: true,
    mfaEnabled: false,
    quarantined: false
  }
];

let auditLog = [];

function validateAdmin(req, res, next) {
  if (
    req.headers["x-admin-token"] !== ADMIN_TOKEN ||
    req.headers["x-mfa"] !== MFA_CODE
  ) {
    return res.status(403).json({ error: "Unauthorized" });
  }
  next();
}

function calculateRisk(identity) {
  let risk =
    identity.privilegeLevel * 0.4 +
    identity.anomalyScore * 0.3 +
    (identity.publicExposure ? 20 : 0) +
    (!identity.mfaEnabled ? 15 : 0);

  return Math.min(Math.floor(risk), 100);
}

app.get("/identities", (req, res) => {
  res.json(
    identities.map(i => ({
      identity: i,
      risk: calculateRisk(i),
      level: calculateRisk(i) >= HIGH_RISK_THRESHOLD ? "HIGH" : "MEDIUM"
    }))
  );
});

app.post("/identities/:id/preview", validateAdmin, (req, res) => {
  const identity = identities.find(i => i.id === req.params.id);
  if (!identity) return res.status(404).json({ error: "Not found" });

  const risk = calculateRisk(identity);

  auditLog.push({
    identity: identity.id,
    action: "preview",
    time: new Date()
  });

  res.json({
    mode: "preview",
    risk,
    recommendedActions: [
      "Disable login",
      "Revoke sessions",
      "Remove elevated roles",
      "Attach deny policy"
    ]
  });
});

app.post("/identities/:id/execute", validateAdmin, (req, res) => {
  const identity = identities.find(i => i.id === req.params.id);
  if (!identity) return res.status(404).json({ error: "Not found" });

  const risk = calculateRisk(identity);
  if (risk < HIGH_RISK_THRESHOLD)
    return res.status(400).json({ error: "Risk below HIGH threshold" });

  identity.quarantined = true;

  auditLog.push({
    identity: identity.id,
    action: "quarantine",
    time: new Date()
  });

  res.json({ status: "Identity quarantined safely", risk });
});

app.get("/audit", (req, res) => {
  res.json(auditLog);
});

app.listen(3000, () => console.log("Security Engine running on port 3000"));
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Metaphysical Domain SOC Control Plane</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>

<style>
:root{
  --bg:#0b1220;
  --panel:#111b2e;
  --border:#23324f;
  --accent:#38bdf8;
  --danger:#ef4444;
  --warn:#fbbf24;
  --good:#22c55e;
  --text:#e6edf7;
  --muted:#94a3b8;
}

body{
  margin:0;
  background:var(--bg);
  color:var(--text);
  font-family:Consolas, monospace;
  display:grid;
  grid-template-columns: 320px 1fr;
  grid-template-rows: 60px 1fr;
  height:100vh;
}

header{
  grid-column:1/3;
  background:var(--panel);
  padding:15px;
  border-bottom:1px solid var(--border);
  color:var(--accent);
}

.sidebar{
  background:var(--panel);
  padding:15px;
  border-right:1px solid var(--border);
  overflow:auto;
}

.main{
  position:relative;
}

.card{
  margin-bottom:15px;
  padding:10px;
  border:1px solid var(--border);
  border-radius:8px;
  background:#0f1830;
}

button{
  width:100%;
  padding:8px;
  margin-top:6px;
  background:#0f1830;
  border:1px solid var(--border);
  color:var(--text);
  border-radius:6px;
  cursor:pointer;
}

button:hover{
  border-color:var(--accent);
}

#topology{
  width:100%;
  height:100%;
}

.log{
  font-size:12px;
  max-height:150px;
  overflow:auto;
  color:var(--muted);
}
</style>
</head>

<body>

<header>
🛰 SOC Control Plane — Preview Mode (No Live Infrastructure Changes)
</header>

<div class="sidebar">

  <div class="card">
    <strong>AI Domain Stability Index</strong>
    <div id="stability">Calculating...</div>
  </div>

  <div class="card">
    <strong>Drift Vectors</strong>
    <div id="drift"></div>
  </div>

  <div class="card">
    <strong>Anomalous Patterns</strong>
    <div id="anomalies"></div>
  </div>

  <div class="card">
    <strong>SOC Actions</strong>
    <button onclick="scan()">Scan Domain</button>
    <button onclick="analyze()">Analyze Drift</button>
    <button onclick="stabilize()">Stabilize (Preview)</button>
    <button onclick="contain()">Contain High Risk (Preview)</button>
  </div>

  <div class="card">
    <strong>Activity Log</strong>
    <div class="log" id="log"></div>
  </div>

</div>

<div class="main">
  <canvas id="topology"></canvas>
</div>

<script>

// ------------------------
// Simulated Data
// ------------------------

let driftVectors = [
  { name:"IAM Policy Escalation", severity:92 },
  { name:"Public Network Exposure", severity:85 },
  { name:"Anomalous API Spike", severity:78 }
];

let anomalies = [
  "Unusual geographic login",
  "High entropy API call frequency",
  "Privilege elevation burst pattern"
];

// ------------------------
// Logging
// ------------------------

function log(message){
  const entry=document.createElement("div");
  entry.textContent=`[${new Date().toLocaleTimeString()}] ${message}`;
  document.getElementById("log").appendChild(entry);
}

// ------------------------
// AI Stability Index
// ------------------------

function calculateStability(){
  let avg = driftVectors.reduce((sum,v)=>sum+v.severity,0)/driftVectors.length;
  let stability = Math.max(100-avg,0);
  document.getElementById("stability").innerHTML =
    `<strong style="color:${stability<50?'#ef4444':'#22c55e'}">${stability.toFixed(1)}%</strong>`;
}

// ------------------------
// Drift + Anomaly Panels
// ------------------------

function renderDrift(){
  const container=document.getElementById("drift");
  container.innerHTML="";
  driftVectors.forEach(v=>{
    container.innerHTML +=
      `<div style="color:${v.severity>85?'#ef4444':'#fbbf24'}">
       ${v.name} — ${v.severity}
       </div>`;
  });
}

function renderAnomalies(){
  const container=document.getElementById("anomalies");
  container.innerHTML="";
  anomalies.forEach(a=>{
    container.innerHTML += `<div>${a}</div>`;
  });
}

// ------------------------
// SOC Actions
// ------------------------

function scan(){
  log("Scanning domain layers...");
}

function analyze(){
  log("Analyzing drift vectors and anomaly signatures...");
}

function stabilize(){
  log("Preview stabilization initiated.");
  alert("Would enforce policy corrections.\nWould reduce exposure.\nWould restore IAM integrity.\n\nPreview only.");
}

function contain(){
  log("Preview containment sequence initiated.");
  alert("Would quarantine high-risk identities.\nWould revoke sessions.\nWould enforce MFA.\n\nPreview only.");
}

// ------------------------
// 3D Topology (Three.js)
// ------------------------

let scene = new THREE.Scene();
let camera = new THREE.PerspectiveCamera(75, window.innerWidth/window.innerHeight, 0.1, 1000);
let renderer = new THREE.WebGLRenderer({canvas:document.getElementById("topology")});
renderer.setSize(window.innerWidth-320, window.innerHeight-60);

let geometry = new THREE.SphereGeometry(1,32,32);
let material = new THREE.MeshBasicMaterial({color:0x38bdf8, wireframe:true});
let centralNode = new THREE.Mesh(geometry,material);
scene.add(centralNode);

camera.position.z=5;

function animate(){
  requestAnimationFrame(animate);
  centralNode.rotation.x+=0.01;
  centralNode.rotation.y+=0.01;
  renderer.render(scene,camera);
}

animate();

// ------------------------

renderDrift();
renderAnomalies();
calculateStability();

</script>

</body>
</html>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Metaphysical Domain SOC Control Plane</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>

<style>
:root{
  --bg:#0b1220;
  --panel:#111b2e;
  --border:#23324f;
  --accent:#38bdf8;
  --danger:#ef4444;
  --warn:#fbbf24;
  --good:#22c55e;
  --text:#e6edf7;
  --muted:#94a3b8;
}

body{
  margin:0;
  background:var(--bg);
  color:var(--text);
  font-family:Consolas, monospace;
  display:grid;
  grid-template-columns: 320px 1fr;
  grid-template-rows: 60px 1fr;
  height:100vh;
}

header{
  grid-column:1/3;
  background:var(--panel);
  padding:15px;
  border-bottom:1px solid var(--border);
  color:var(--accent);
}

.sidebar{
  background:var(--panel);
  padding:15px;
  border-right:1px solid var(--border);
  overflow:auto;
}

.main{
  position:relative;
}

.card{
  margin-bottom:15px;
  padding:10px;
  border:1px solid var(--border);
  border-radius:8px;
  background:#0f1830;
}

button{
  width:100%;
  padding:8px;
  margin-top:6px;
  background:#0f1830;
  border:1px solid var(--border);
  color:var(--text);
  border-radius:6px;
  cursor:pointer;
}

button:hover{
  border-color:var(--accent);
}

#topology{
  width:100%;
  height:100%;
}

.log{
  font-size:12px;
  max-height:150px;
  overflow:auto;
  color:var(--muted);
}
</style>
</head>

<body>

<header>
🛰 SOC Control Plane — Preview Mode (No Live Infrastructure Changes)
</header>

<div class="sidebar">

  <div class="card">
    <strong>AI Domain Stability Index</strong>
    <div id="stability">Calculating...</div>
  </div>

  <div class="card">
    <strong>Drift Vectors</strong>
    <div id="drift"></div>
  </div>

  <div class="card">
    <strong>Anomalous Patterns</strong>
    <div id="anomalies"></div>
  </div>

  <div class="card">
    <strong>SOC Actions</strong>
    <button onclick="scan()">Scan Domain</button>
    <button onclick="analyze()">Analyze Drift</button>
    <button onclick="stabilize()">Stabilize (Preview)</button>
    <button onclick="contain()">Contain High Risk (Preview)</button>
  </div>

  <div class="card">
    <strong>Activity Log</strong>
    <div class="log" id="log"></div>
  </div>

</div>

<div class="main">
  <canvas id="topology"></canvas>
</div>

<script>

// ------------------------
// Simulated Data
// ------------------------

let driftVectors = [
  { name:"IAM Policy Escalation", severity:92 },
  { name:"Public Network Exposure", severity:85 },
  { name:"Anomalous API Spike", severity:78 }
];

let anomalies = [
  "Unusual geographic login",
  "High entropy API call frequency",
  "Privilege elevation burst pattern"
];

// ------------------------
// Logging
// ------------------------

function log(message){
  const entry=document.createElement("div");
  entry.textContent=`[${new Date().toLocaleTimeString()}] ${message}`;
  document.getElementById("log").appendChild(entry);
}

// ------------------------
// AI Stability Index
// ------------------------

function calculateStability(){
  let avg = driftVectors.reduce((sum,v)=>sum+v.severity,0)/driftVectors.length;
  let stability = Math.max(100-avg,0);
  document.getElementById("stability").innerHTML =
    `<strong style="color:${stability<50?'#ef4444':'#22c55e'}">${stability.toFixed(1)}%</strong>`;
}

// ------------------------
// Drift + Anomaly Panels
// ------------------------

function renderDrift(){
  const container=document.getElementById("drift");
  container.innerHTML="";
  driftVectors.forEach(v=>{
    container.innerHTML +=
      `<div style="color:${v.severity>85?'#ef4444':'#fbbf24'}">
       ${v.name} — ${v.severity}
       </div>`;
  });
}

function renderAnomalies(){
  const container=document.getElementById("anomalies");
  container.innerHTML="";
  anomalies.forEach(a=>{
    container.innerHTML += `<div>${a}</div>`;
  });
}

// ------------------------
// SOC Actions
// ------------------------

function scan(){
  log("Scanning domain layers...");
}

function analyze(){
  log("Analyzing drift vectors and anomaly signatures...");
}

function stabilize(){
  log("Preview stabilization initiated.");
  alert("Would enforce policy corrections.\nWould reduce exposure.\nWould restore IAM integrity.\n\nPreview only.");
}

function contain(){
  log("Preview containment sequence initiated.");
  alert("Would quarantine high-risk identities.\nWould revoke sessions.\nWould enforce MFA.\n\nPreview only.");
}

// ------------------------
// 3D Topology (Three.js)
// ------------------------

let scene = new THREE.Scene();
let camera = new THREE.PerspectiveCamera(75, window.innerWidth/window.innerHeight, 0.1, 1000);
let renderer = new THREE.WebGLRenderer({canvas:document.getElementById("topology")});
renderer.setSize(window.innerWidth-320, window.innerHeight-60);

let geometry = new THREE.SphereGeometry(1,32,32);
let material = new THREE.MeshBasicMaterial({color:0x38bdf8, wireframe:true});
let centralNode = new THREE.Mesh(geometry,material);
scene.add(centralNode);

camera.position.z=5;

function animate(){
  requestAnimationFrame(animate);
  centralNode.rotation.x+=0.01;
  centralNode.rotation.y+=0.01;
  renderer.render(scene,camera);
}

animate();

// ------------------------

renderDrift();
renderAnomalies();
calculateStability();

</script>

</body>
</html>
import math
import re
from collections import Counter
from datetime import datetime
from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Optional

app = FastAPI(title="Entropy Outlier Scanner (Preview)")

# Heuristic: strings that look like tokens/keys (base64-ish, hex, jwt-ish)
CANDIDATE_RE = re.compile(
    r"""(
        [A-Za-z0-9+/=]{24,} |                 # base64-ish
        [a-fA-F0-9]{32,} |                    # long hex
        eyJ[A-Za-z0-9_-]+?\.[A-Za-z0-9_-]+?\.[A-Za-z0-9_-]+  # JWT-ish
    )""",
    re.VERBOSE
)

class ScanRequest(BaseModel):
    text: str
    source: Optional[str] = "manual"
    min_len: int = 24
    entropy_threshold: float = 4.2  # tweak: 0..~6.0 for typical alphabets

class EntropicEntity(BaseModel):
    value_preview: str
    length: int
    shannon_entropy: float
    kind: str
    confidence: str
    suggested_actions: List[str]

class ScanResponse(BaseModel):
    scanned_at: str
    source: str
    entities: List[EntropicEntity]

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent

def classify(s: str) -> str:
    if s.startswith("eyJ") and s.count(".") == 2:
        return "jwt-like"
    if re.fullmatch(r"[a-fA-F0-9]{32,}", s or ""):
        return "hex-like"
    if re.fullmatch(r"[A-Za-z0-9+/=]{24,}", s or ""):
        return "base64-like"
    return "unknown"

def confidence(ent: float, length: int) -> str:
    # simple heuristic
    if ent >= 4.8 and length >= 32:
        return "high"
    if ent >= 4.2 and length >= 24:
        return "medium"
    return "low"

def preview_actions(kind: str) -> List[str]:
    # preview-only recommendations
    base = [
        "Preview: open investigation ticket",
        "Preview: search occurrences across logs/repos",
        "Preview: check IAM/Entra activity around timestamp",
    ]
    if kind in ("jwt-like", "base64-like", "hex-like"):
        base += [
            "Preview: rotate suspected credential/secret",
            "Preview: revoke sessions / invalidate tokens (if applicable)",
            "Preview: add secret scanning + DLP guardrail",
        ]
    return base

@app.post("/scan", response_model=ScanResponse)
def scan(req: ScanRequest):
    candidates = set()
    for match in CANDIDATE_RE.finditer(req.text or ""):
        s = match.group(0)
        if len(s) >= req.min_len:
            candidates.add(s)

    entities: List[EntropicEntity] = []
    for s in sorted(candidates, key=len, reverse=True):
        ent = shannon_entropy(s)
        if ent < req.entropy_threshold:
            continue

        k = classify(s)
        conf = confidence(ent, len(s))
        entities.append(
            EntropicEntity(
                value_preview=(s[:10] + "…" + s[-6:]) if len(s) > 20 else s,
                length=len(s),
                shannon_entropy=round(ent, 3),
                kind=k,
                confidence=conf,
                suggested_actions=preview_actions(k),
            )
        )

    return ScanResponse(
        scanned_at=datetime.utcnow().isoformat() + "Z",
        source=req.source or "manual",
        entities=entities
    )
uvicorn entropy_api:app --reload --port 8080
#!/usr/bin/env python3
"""
entropy_to_cloud.py
Preview-first publisher for entropy outlier findings.

AWS target (implemented): CloudWatch Logs
Azure target (skeleton): Log Analytics (left as hook; needs workspace + key)
"""

import argparse, hashlib, json, math, os, re, time
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List, Any

CANDIDATE_RE = re.compile(
    r"""(
        [A-Za-z0-9+/=]{24,} |
        [a-fA-F0-9]{32,} |
        eyJ[A-Za-z0-9_-]+?\.[A-Za-z0-9_-]+?\.[A-Za-z0-9_-]+
    )""",
    re.VERBOSE
)

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent

def classify(s: str) -> str:
    if s.startswith("eyJ") and s.count(".") == 2:
        return "jwt-like"
    if re.fullmatch(r"[a-fA-F0-9]{32,}", s or ""):
        return "hex-like"
    if re.fullmatch(r"[A-Za-z0-9+/=]{24,}", s or ""):
        return "base64-like"
    return "unknown"

def redact_preview(s: str) -> str:
    if len(s) <= 18:
        return s
    return f"{s[:10]}…{s[-6:]}"

def stable_hash(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def extract_findings(text: str, source: str, threshold: float, min_len: int) -> List[Dict[str, Any]]:
    found = set()
    for m in CANDIDATE_RE.finditer(text or ""):
        s = m.group(0)
        if len(s) >= min_len:
            found.add(s)

    findings = []
    now = datetime.now(timezone.utc).isoformat()
    for s in sorted(found, key=len, reverse=True):
        ent = shannon_entropy(s)
        if ent < threshold:
            continue

        kind = classify(s)
        finding = {
            "time_utc": now,
            "source": source,
            "entity_kind": kind,
            "entity_len": len(s),
            "entity_entropy": round(ent, 3),
            "entity_preview": redact_preview(s),     # redacted
            "entity_sha256": stable_hash(s),         # safe fingerprint for correlation
            "severity": "HIGH" if ent >= 4.8 and len(s) >= 32 else ("MED" if ent >= 4.2 else "LOW"),
            "note": "Entropy outlier indicator (redacted). Treat as potential secret/token/leak indicator."
        }
        findings.append(finding)
    return findings

# ---------- AWS: CloudWatch Logs publisher ----------
def aws_publish_cloudwatch(findings: List[Dict[str, Any]], group: str, stream: str, preview: bool):
    try:
        import boto3
        from botocore.exceptions import ClientError
    except Exception as e:
        raise RuntimeError("boto3 is required for AWS publishing: pip install boto3") from e

    logs = boto3.client("logs")

    # Ensure log group + stream exist
    def ensure():
        try:
            logs.create_log_group(logGroupName=group)
        except Exception:
            pass
        try:
            logs.create_log_stream(logGroupName=group, logStreamName=stream)
        except Exception:
            pass

    ensure()

    events = []
    for f in findings:
        events.append({
            "timestamp": int(time.time() * 1000),
            "message": json.dumps(f, separators=(",", ":"))
        })

    if preview:
        print("\n=== PREVIEW: CloudWatch put_log_events payload ===")
        print(json.dumps({"logGroupName": group, "logStreamName": stream, "events": events[:5]}, indent=2))
        print(f"... ({len(events)} total events)")
        return

    # Get sequence token if needed
    seq = None
    try:
        resp = logs.describe_log_streams(
            logGroupName=group,
            logStreamNamePrefix=stream,
            limit=1
        )
        streams = resp.get("logStreams", [])
        if streams:
            seq = streams[0].get("uploadSequenceToken")
    except Exception:
        seq = None

    kwargs = dict(logGroupName=group, logStreamName=stream, logEvents=events)
    if seq:
        kwargs["sequenceToken"] = seq

    logs.put_log_events(**kwargs)

# ---------- Azure: Log Analytics hook (skeleton) ----------
def azure_publish_log_analytics(findings: List[Dict[str, Any]], preview: bool):
    """
    To implement for real you need:
      - workspace_id
      - shared_key
      - a custom table name
    Then POST findings as JSON to the Log Analytics Data Collector API.
    (Preview prints the payload you would send.)
    """
    payload = {"records": findings[:5], "count_total": len(findings)}
    if preview:
        print("\n=== PREVIEW: Azure Log Analytics payload ===")
        print(json.dumps(payload, indent=2))
        return
    raise NotImplementedError("Azure publishing requires workspace_id + shared_key; wire it in if you want.")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", help="Path to a text/log file to scan", required=True)
    ap.add_argument("--source", default="manual", help="Source label (cloudtrail, activitylog, etc.)")
    ap.add_argument("--threshold", type=float, default=4.2, help="Entropy threshold")
    ap.add_argument("--min-len", type=int, default=24, help="Minimum candidate length")
    ap.add_argument("--provider", choices=["aws", "azure"], required=True)
    ap.add_argument("--preview", action="store_true", help="Preview only; do not publish")
    # AWS options
    ap.add_argument("--cw-group", default="/soc/entropy-findings")
    ap.add_argument("--cw-stream", default="entropy-outliers")
    args = ap.parse_args()

    text = open(args.input, "r", encoding="utf-8", errors="ignore").read()
    findings = extract_findings(text, args.source, args.threshold, args.min_len)

    print(f"Findings: {len(findings)} (threshold={args.threshold}, min_len={args.min_len})")
    if not findings:
        return

    if args.provider == "aws":
        aws_publish_cloudwatch(findings, args.cw_group, args.cw_stream, args.preview)
        print("\nView in AWS: CloudWatch Logs Insights on log group:", args.cw_group)
        print("Example query: fields @timestamp, severity, entity_kind, entity_entropy, entity_preview, source | sort @timestamp desc")
    else:
        azure_publish_log_analytics(findings, args.preview)
        print("\nView in Azure: Log Analytics (custom table) / Sentinel workbook once wired.")

if __name__ == "__main__":
    main()
python entropy_to_cloud.py --input sample.log --source cloudtrail --provider aws --preview
# Requires AWS credentials in env/profile + boto3 installed
pip install boto3
python entropy_to_cloud.py --input sample.log --source cloudtrail --provider aws \
  --cw-group /soc/entropy-findings --cw-stream entropy-outliers
# Requires AWS credentials in env/profile + boto3 installed
pip install boto3
python entropy_to_cloud.py --input sample.log --source cloudtrail --provider aws \
  --cw-group /soc/entropy-findings --cw-stream entropy-outliers
#!/usr/bin/env python3
"""
entropy_findings_multicloud.py

Preview-first: extracts entropy outliers from text/log files and publishes
redacted "findings" to:
  - AWS CloudWatch Logs
  - Azure Log Analytics (Data Collector API)

SAFETY:
  - Never sends full token values
  - Sends only (preview + sha256 fingerprint + metadata)
"""

import argparse, base64, hashlib, hmac, json, math, os, re, time
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

import requests

CANDIDATE_RE = re.compile(
    r"""(
        [A-Za-z0-9+/=]{24,} |
        [a-fA-F0-9]{32,} |
        eyJ[A-Za-z0-9_-]+?\.[A-Za-z0-9_-]+?\.[A-Za-z0-9_-]+
    )""",
    re.VERBOSE
)

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent

def classify(s: str) -> str:
    if s.startswith("eyJ") and s.count(".") == 2:
        return "jwt-like"
    if re.fullmatch(r"[a-fA-F0-9]{32,}", s or ""):
        return "hex-like"
    if re.fullmatch(r"[A-Za-z0-9+/=]{24,}", s or ""):
        return "base64-like"
    return "unknown"

def redact_preview(s: str) -> str:
    if len(s) <= 18:
        return s
    return f"{s[:10]}…{s[-6:]}"

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def severity(ent: float, length: int) -> str:
    if ent >= 4.8 and length >= 32:
        return "HIGH"
    if ent >= 4.2 and length >= 24:
        return "MED"
    return "LOW"

def extract_findings(text: str, source: str, threshold: float, min_len: int) -> List[Dict[str, Any]]:
    found = set()
    for m in CANDIDATE_RE.finditer(text or ""):
        s = m.group(0)
        if len(s) >= min_len:
            found.add(s)

    now = datetime.now(timezone.utc).isoformat()
    findings = []
    for s in sorted(found, key=len, reverse=True):
        ent = shannon_entropy(s)
        if ent < threshold:
            continue

        kind = classify(s)
        findings.append({
            "time_utc": now,
            "source": source,
            "entity_kind": kind,
            "entity_len": len(s),
            "entity_entropy": round(ent, 3),
            "entity_preview": redact_preview(s),   # redacted
            "entity_sha256": sha256_hex(s),        # fingerprint for correlation
            "severity": severity(ent, len(s)),
            "note": "Entropy outlier indicator (redacted). Treat as potential secret/token/leak indicator."
        })
    return findings

# -------------------------
# AWS: CloudWatch Logs
# -------------------------
def aws_publish_cloudwatch(findings: List[Dict[str, Any]], group: str, stream: str, preview: bool):
    import boto3
    logs = boto3.client("logs")

    def ensure_group_stream():
        try:
            logs.create_log_group(logGroupName=group)
        except Exception:
            pass
        try:
            logs.create_log_stream(logGroupName=group, logStreamName=stream)
        except Exception:
            pass

    ensure_group_stream()

    events = [{"timestamp": int(time.time() * 1000), "message": json.dumps(f, separators=(",", ":"))} for f in findings]

    if preview:
        print("\n=== PREVIEW: AWS CloudWatch put_log_events ===")
        print(json.dumps({"logGroupName": group, "logStreamName": stream, "events": events[:5]}, indent=2))
        print(f"... ({len(events)} total events)")
        return

    # sequence token handling
    seq = None
    try:
        resp = logs.describe_log_streams(logGroupName=group, logStreamNamePrefix=stream, limit=1)
        streams = resp.get("logStreams", [])
        if streams:
            seq = streams[0].get("uploadSequenceToken")
    except Exception:
        seq = None

    kwargs = dict(logGroupName=group, logStreamName=stream, logEvents=events)
    if seq:
        kwargs["sequenceToken"] = seq

    logs.put_log_events(**kwargs)
    print(f"\nAWS published {len(events)} events to CloudWatch Logs group={group}, stream={stream}")

# -------------------------
# Azure: Log Analytics Data Collector API
# -------------------------
def _build_azure_signature(workspace_id: str, shared_key: str, date_rfc1123: str, content_length: int, method: str, content_type: str, resource: str):
    x_headers = f"x-ms-date:{date_rfc1123}"
    string_to_hash = f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
    decoded_key = base64.b64decode(shared_key)
    hashed = hmac.new(decoded_key, string_to_hash.encode("utf-8"), hashlib.sha256).digest()
    encoded_hash = base64.b64encode(hashed).decode("utf-8")
    return f"SharedKey {workspace_id}:{encoded_hash}"

def azure_publish_log_analytics(findings: List[Dict[str, Any]], workspace_id: str, shared_key: str, log_type: str, preview: bool):
    """
    Writes to a custom table named <log_type>_CL in Log Analytics.
    Example log_type: EntropyFindings  -> table: EntropyFindings_CL
    """
    body = json.dumps(findings)
    method = "POST"
    content_type = "application/json"
    resource = "/api/logs"
    date_rfc1123 = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    content_length = len(body)

    if preview:
        print("\n=== PREVIEW: Azure Log Analytics Data Collector POST ===")
        print("POST https://<workspaceId>.ods.opinsights.azure.com/api/logs?api-version=2016-04-01")
        print("Log-Type:", log_type)
        print("Body sample:", json.dumps(findings[:3], indent=2))
        print(f"... ({len(findings)} total records)")
        return

    signature = _build_azure_signature(workspace_id, shared_key, date_rfc1123, content_length, method, content_type, resource)
    uri = f"https://{workspace_id}.ods.opinsights.azure.com{resource}?api-version=2016-04-01"
    headers = {
        "Content-Type": content_type,
        "Log-Type": log_type,
        "x-ms-date": date_rfc1123,
        "Authorization": signature
    }

    resp = requests.post(uri, data=body, headers=headers, timeout=30)
    if resp.status_code not in (200, 202):
        raise RuntimeError(f"Azure publish failed: {resp.status_code} {resp.text}")
    print(f"\nAzure published {len(findings)} records to Log Analytics table {log_type}_CL")

# -------------------------
# Query packs (view layer)
# -------------------------
def print_query_pack_aws(group: str):
    print("\n=== AWS CloudWatch Logs Insights Query Pack ===")
    print(f"Log group: {group}\n")
    print("""1) Latest HIGH severity
fields @timestamp, @message
| parse @message /"severity":"(?<severity>[^"]+)"/
| parse @message /"entity_kind":"(?<kind>[^"]+)"/
| parse @message /"entity_entropy":(?<entropy>[0-9.]+)/
| parse @message /"entity_preview":"(?<preview>[^"]+)"/
| parse @message /"source":"(?<source>[^"]+)"/
| filter severity="HIGH"
| sort @timestamp desc
| limit 50
""")
    print("""2) Trend over time (count by severity)
fields @timestamp, @message
| parse @message /"severity":"(?<severity>[^"]+)"/
| stats count() as findings by bin(5m), severity
| sort bin(5m) desc
""")
    print("""3) Top repeated fingerprints (correlation)
fields @timestamp, @message
| parse @message /"entity_sha256":"(?<fp>[^"]+)"/
| parse @message /"severity":"(?<severity>[^"]+)"/
| stats count() as hits, latest(@timestamp) as last_seen by fp, severity
| sort hits desc
| limit 50
""")

def print_query_pack_azure(log_type: str):
    table = f"{log_type}_CL"
    print("\n=== Azure Log Analytics / Sentinel KQL Query Pack ===")
    print(f"Table: {table}\n")
    print(f"""1) Latest HIGH severity
{table}
| where severity_s == "HIGH"
| project TimeGenerated, source_s, entity_kind_s, entity_entropy_d, entity_len_d, entity_preview_s, entity_sha256_s
| order by TimeGenerated desc
| take 50
""")
    print(f"""2) Trend (5m bins)
{table}
| summarize findings=count() by bin(TimeGenerated, 5m), severity_s
| order by TimeGenerated desc
""")
    print(f"""3) Top repeated fingerprints (correlation)
{table}
| summarize hits=count(), last_seen=max(TimeGenerated) by entity_sha256_s, severity_s
| order by hits desc
| take 50
""")
    print(f"""4) “Source hotspots” (where are they coming from)
{table}
| summarize findings=count() by source_s, severity_s
| order by findings desc
""")

# -------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="Path to a text/log file to scan")
    ap.add_argument("--source", default="manual", help="Source label (cloudtrail, activitylog, repo-scan, etc.)")
    ap.add_argument("--threshold", type=float, default=4.2, help="Entropy threshold")
    ap.add_argument("--min-len", type=int, default=24, help="Minimum candidate length")
    ap.add_argument("--preview", action="store_true", help="Preview only (do not publish)")
    ap.add_argument("--publish", choices=["aws", "azure", "both"], required=True)

    # AWS options
    ap.add_argument("--cw-group", default="/soc/entropy-findings")
    ap.add_argument("--cw-stream", default="entropy-outliers")

    # Azure options
    ap.add_argument("--la-workspace-id", default=os.getenv("LA_WORKSPACE_ID", ""))
    ap.add_argument("--la-shared-key", default=os.getenv("LA_SHARED_KEY", ""))
    ap.add_argument("--la-log-type", default="EntropyFindings")

    args = ap.parse_args()

    text = open(args.input, "r", encoding="utf-8", errors="ignore").read()
    findings = extract_findings(text, args.source, args.threshold, args.min_len)

    print(f"Findings extracted: {len(findings)} (threshold={args.threshold}, min_len={args.min_len})")
    if not findings:
        print("No findings; nothing to publish.")
        return

    if args.publish in ("aws", "both"):
        aws_publish_cloudwatch(findings, args.cw_group, args.cw_stream, args.preview)
        print_query_pack_aws(args.cw_group)

    if args.publish in ("azure", "both"):
        if not args.preview and (not args.la_workspace_id or not args.la_shared_key):
            raise SystemExit("Azure publish requires --la-workspace-id and --la-shared-key (or env LA_WORKSPACE_ID/LA_SHARED_KEY).")
        azure_publish_log_analytics(findings, args.la_workspace_id, args.la_shared_key, args.la_log_type, args.preview)
        print_query_pack_azure(args.la_log_type)

if __name__ == "__main__":
    main()
python entropy_findings_multicloud.py \
  --input sample.log \
  --source cloudtrail \
  --publish both \
  --preview
python entropy_findings_multicloud.py \
  --input sample.log \
  --source cloudtrail \
  --publish aws \
  --cw-group /soc/entropy-findings \
  --cw-stream entropy-outliers
export LA_WORKSPACE_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export LA_SHARED_KEY="BASE64_SHARED_KEY_FROM_LOG_ANALYTICS"

python entropy_findings_multicloud.py \
  --input sample.log \
  --source activitylog \
  --publish azure \
  --la-log-type EntropyFindings
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>The Cloud (Preview) — SOC Visualization</title>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
  <style>
    :root{
      --bg:#0b1220; --panel:#111b2e; --border:#23324f;
      --text:#e6edf7; --muted:#9fb0c8; --accent:#38bdf8;
      --bad:#ef4444; --warn:#fbbf24; --good:#22c55e;
    }
    body{
      margin:0; background:var(--bg); color:var(--text);
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      height:100vh; display:grid;
      grid-template-columns: 360px 1fr;
      grid-template-rows: 60px 1fr;
    }
    header{
      grid-column:1/3;
      background:var(--panel);
      border-bottom:1px solid var(--border);
      display:flex; align-items:center; padding:0 16px;
      color:var(--accent); font-weight:800;
    }
    .sidebar{
      background:var(--panel);
      border-right:1px solid var(--border);
      padding:14px;
      overflow:auto;
    }
    .main{
      position:relative;
    }
    .card{
      background:#0f1830;
      border:1px solid var(--border);
      border-radius:12px;
      padding:12px;
      margin-bottom:12px;
    }
    .row{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
    .right{ margin-left:auto; }
    .pill{
      border:1px solid var(--border);
      padding:4px 10px;
      border-radius:999px;
      color:var(--muted);
      font-size:12px;
    }
    .kpi{
      font-size:28px; font-weight:900; letter-spacing:0.3px;
      margin-top:6px;
    }
    .muted{ color:var(--muted); font-size:12px; line-height:1.35; }
    button, select{
      width:100%;
      background:#0b1220;
      border:1px solid var(--border);
      color:var(--text);
      padding:10px;
      border-radius:10px;
      cursor:pointer;
      font-family:inherit;
      font-size:13px;
    }
    button:hover, select:hover{ border-color:var(--accent); }
    .btn-warn{ border-color:var(--warn); }
    .btn-bad{ border-color:var(--bad); }
    .btn-good{ border-color:var(--good); }
    .log{
      background:#0b1220;
      border:1px solid var(--border);
      border-radius:12px;
      padding:10px;
      color:var(--muted);
      font-size:12px;
      white-space:pre-wrap;
      max-height:170px;
      overflow:auto;
    }
    canvas{ width:100%; height:100%; display:block; }
    .hud{
      position:absolute;
      left:14px; bottom:14px;
      background:rgba(15,24,48,0.78);
      border:1px solid rgba(35,50,79,0.9);
      padding:10px 12px;
      border-radius:12px;
      color:var(--muted);
      font-size:12px;
      max-width:520px;
      backdrop-filter: blur(6px);
    }
    .hud strong{ color:var(--text); }
  </style>
</head>

<body>
  <header>
    🌥 The Cloud (Preview) — 3D SOC Abstraction
    <span class="right pill">Preview mode • No live infrastructure changes</span>
  </header>

  <div class="sidebar">
    <div class="card">
      <div class="row">
        <strong>Domain Stability Index</strong>
        <span class="right pill" id="modePill">SIMULATED AI</span>
      </div>
      <div class="kpi" id="stabilityKpi">—</div>
      <div class="muted">
        Stability is computed from drift/anomaly intensity. In a real build, this would be fed by CloudTrail / Activity Logs / Config / Defender.
      </div>
    </div>

    <div class="card">
      <strong>View</strong>
      <div class="row" style="margin-top:10px;">
        <select id="viewSelect">
          <option value="balanced">Balanced (default)</option>
          <option value="drift">Drift focus</option>
          <option value="anomaly">Anomaly focus</option>
          <option value="quiet">Quiet / stable</option>
        </select>
      </div>
      <div class="muted" style="margin-top:8px;">
        This changes the geometry: more drift beams, stronger anomaly pulses, or calm stabilization.
      </div>
    </div>

    <div class="card">
      <strong>SOC Actions (Preview)</strong>
      <div class="row" style="margin-top:10px;">
        <button class="btn-warn" id="scanBtn">Scan Cloud</button>
        <button class="btn-warn" id="analyzeBtn">Analyze Drift</button>
        <button class="btn-good" id="stabilizeBtn">Stabilize (Preview)</button>
        <button class="btn-bad" id="containBtn">Contain High Risk (Preview)</button>
      </div>
      <div class="muted" style="margin-top:8px;">
        These actions only alter the visualization and write audit logs. They do not affect AWS/Azure.
      </div>
    </div>

    <div class="card">
      <strong>Drift Vectors (Simulated)</strong>
      <div class="muted" id="driftList" style="margin-top:8px;"></div>
    </div>

    <div class="card">
      <strong>Anomalous Patterns (Simulated)</strong>
      <div class="muted" id="anomList" style="margin-top:8px;"></div>
    </div>

    <div class="card">
      <strong>Audit Stream</strong>
      <div class="log" id="audit"></div>
    </div>
  </div>

  <div class="main">
    <canvas id="c"></canvas>
    <div class="hud" id="hud">
      <strong>Tip:</strong> Click+drag to orbit. Scroll to zoom.<br/>
      <span id="hudLine">Rendering a cloud volume, control-plane core, service nodes, drift vectors, anomaly pulses.</span>
    </div>
  </div>

<script>
(() => {
  // -----------------------------
  // Helpers
  // -----------------------------
  const $ = (id) => document.getElementById(id);
  function log(msg){
    $("audit").textContent += `[${new Date().toISOString()}] ${msg}\n`;
    $("audit").scrollTop = $("audit").scrollHeight;
  }

  // -----------------------------
  // Simulated “cloud state”
  // -----------------------------
  const driftVectors = [
    { name:"IAM policy escalation", severity:92 },
    { name:"Public ingress exposure", severity:86 },
    { name:"Key-rotation drift", severity:71 },
  ];
  const anomalies = [
    { name:"Unusual geo sign-in", severity:88 },
    { name:"API call burst entropy", severity:79 },
    { name:"Role assumption anomaly", severity:74 },
  ];

  function renderLists(){
    $("driftList").innerHTML = driftVectors.map(v => `• ${v.name} — ${v.severity}`).join("<br>");
    $("anomList").innerHTML = anomalies.map(a => `• ${a.name} — ${a.severity}`).join("<br>");
  }
  renderLists();

  // Stability index (simulated)
  let driftIntensity = 0.65;   // 0..1
  let anomalyIntensity = 0.55; // 0..1
  let calmness = 0.20;         // 0..1

  function updateStabilityKpi(){
    // Higher drift/anomaly => lower stability; calmness offsets
    const avg = (driftIntensity + anomalyIntensity) / 2;
    const stability = Math.max(0, Math.min(100, 100 - (avg * 90) + (calmness * 20)));
    const s = stability.toFixed(1);
    $("stabilityKpi").textContent = `${s}%`;

    // Color feel by class
    const el = $("stabilityKpi");
    el.style.color = stability < 50 ? "#ef4444" : (stability < 75 ? "#fbbf24" : "#22c55e");
  }
  updateStabilityKpi();

  // -----------------------------
  // Three.js scene
  // -----------------------------
  const canvas = $("c");
  const renderer = new THREE.WebGLRenderer({ canvas, antialias:true });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

  const scene = new THREE.Scene();
  scene.fog = new THREE.FogExp2(0x0b1220, 0.08);

  const camera = new THREE.PerspectiveCamera(60, 1, 0.1, 200);
  camera.position.set(0, 4, 18);

  // Simple orbit controls (no extra libs)
  let isDown = false, lastX=0, lastY=0;
  let yaw = 0.0, pitch = 0.15, dist = 18;

  function updateCamera(){
    const x = dist * Math.sin(yaw) * Math.cos(pitch);
    const y = dist * Math.sin(pitch);
    const z = dist * Math.cos(yaw) * Math.cos(pitch);
    camera.position.set(x, y, z);
    camera.lookAt(0, 0, 0);
  }
  updateCamera();

  canvas.addEventListener("mousedown", (e)=>{ isDown=true; lastX=e.clientX; lastY=e.clientY; });
  window.addEventListener("mouseup", ()=>{ isDown=false; });
  window.addEventListener("mousemove", (e)=>{
    if(!isDown) return;
    const dx = (e.clientX - lastX) * 0.005;
    const dy = (e.clientY - lastY) * 0.005;
    yaw -= dx;
    pitch = Math.max(-1.2, Math.min(1.2, pitch - dy));
    lastX=e.clientX; lastY=e.clientY;
    updateCamera();
  });
  window.addEventListener("wheel", (e)=>{
    dist = Math.max(8, Math.min(40, dist + e.deltaY * 0.01));
    updateCamera();
  }, { passive:true });

  // Lights (soft)
  scene.add(new THREE.AmbientLight(0xffffff, 0.55));
  const key = new THREE.DirectionalLight(0xffffff, 0.8);
  key.position.set(6, 10, 8);
  scene.add(key);

  // Cloud volume (particles)
  const cloudCount = 2600;
  const cloudGeom = new THREE.BufferGeometry();
  const cloudPos = new Float32Array(cloudCount * 3);
  const cloudAlpha = new Float32Array(cloudCount);
  for(let i=0;i<cloudCount;i++){
    // Random points in a soft sphere
    const r = Math.cbrt(Math.random()) * 9.5;
    const th = Math.random() * Math.PI * 2;
    const ph = Math.acos(2*Math.random() - 1);
    const x = r * Math.sin(ph) * Math.cos(th);
    const y = r * Math.cos(ph) * 0.65; // flatten slightly
    const z = r * Math.sin(ph) * Math.sin(th);
    cloudPos[i*3+0]=x;
    cloudPos[i*3+1]=y;
    cloudPos[i*3+2]=z;
    cloudAlpha[i]=0.15 + Math.random()*0.35;
  }
  cloudGeom.setAttribute("position", new THREE.BufferAttribute(cloudPos, 3));
  cloudGeom.setAttribute("alpha", new THREE.BufferAttribute(cloudAlpha, 1));

  const cloudMat = new THREE.PointsMaterial({
    color: 0x7dd3fc,
    size: 0.12,
    transparent: true,
    opacity: 0.22,
    depthWrite: false
  });
  const cloud = new THREE.Points(cloudGeom, cloudMat);
  scene.add(cloud);

  // Cloud control-plane core
  const core = new THREE.Mesh(
    new THREE.IcosahedronGeometry(1.8, 2),
    new THREE.MeshStandardMaterial({ color:0x38bdf8, emissive:0x0b2b45, metalness:0.2, roughness:0.35 })
  );
  scene.add(core);

  // Service nodes (compute/storage/identity/network)
  const nodeDefs = [
    { name:"Compute",  color:0x22c55e, pos:[ 5.2,  1.3,  0.8] },
    { name:"Storage",  color:0xfbbf24, pos:[-4.7, -0.8,  2.8] },
    { name:"Identity", color:0xef4444, pos:[ 1.0, -2.4, -5.2] },
    { name:"Network",  color:0x38bdf8, pos:[-1.2,  2.8, -4.5] },
    { name:"Logging",  color:0x9fb0c8, pos:[ 3.8, -1.9,  4.6] },
  ];

  const nodes = [];
  for(const nd of nodeDefs){
    const m = new THREE.Mesh(
      new THREE.SphereGeometry(0.55, 18, 18),
      new THREE.MeshStandardMaterial({ color: nd.color, emissive:0x111111, metalness:0.1, roughness:0.4 })
    );
    m.position.set(...nd.pos);
    scene.add(m);
    nodes.push(m);

    // Link line to core
    const pts = [new THREE.Vector3(0,0,0), new THREE.Vector3(...nd.pos)];
    const g = new THREE.BufferGeometry().setFromPoints(pts);
    const l = new THREE.Line(g, new THREE.LineBasicMaterial({ color:0x23324f, transparent:true, opacity:0.9 }));
    scene.add(l);
  }

  // Drift vectors (beams) + anomaly pulses (rings)
  const driftGroup = new THREE.Group();
  const anomalyGroup = new THREE.Group();
  scene.add(driftGroup);
  scene.add(anomalyGroup);

  function rebuildDrift(){
    while(driftGroup.children.length) driftGroup.remove(driftGroup.children[0]);

    const beamCount = Math.floor(2 + driftIntensity * 10);
    for(let i=0;i<beamCount;i++){
      const from = nodeDefs[Math.floor(Math.random()*nodeDefs.length)].pos;
      const to = [
        (Math.random()-0.5)*10,
        (Math.random()-0.5)*6,
        (Math.random()-0.5)*10
      ];
      const pts = [new THREE.Vector3(...from), new THREE.Vector3(...to)];
      const g = new THREE.BufferGeometry().setFromPoints(pts);
      const c = driftIntensity > 0.7 ? 0xef4444 : 0xfbbf24;
      const l = new THREE.Line(g, new THREE.LineBasicMaterial({ color:c, transparent:true, opacity:0.55 }));
      driftGroup.add(l);
    }
  }

  function rebuildAnomalies(){
    while(anomalyGroup.children.length) anomalyGroup.remove(anomalyGroup.children[0]);

    const ringCount = Math.floor(1 + anomalyIntensity * 6);
    for(let i=0;i<ringCount;i++){
      const r = 1.6 + Math.random()*3.8;
      const ring = new THREE.Mesh(
        new THREE.RingGeometry(r, r+0.08, 64),
        new THREE.MeshBasicMaterial({ color:0x7dd3fc, transparent:true, opacity:0.22, side:THREE.DoubleSide })
      );
      ring.rotation.x = Math.random()*Math.PI;
      ring.rotation.y = Math.random()*Math.PI;
      ring.rotation.z = Math.random()*Math.PI;
      ring.userData.pulse = 0.6 + Math.random()*1.2;
      anomalyGroup.add(ring);
    }
  }

  rebuildDrift();
  rebuildAnomalies();

  // Resize
  function resize(){
    const w = window.innerWidth - 360;
    const h = window.innerHeight - 60;
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  }
  window.addEventListener("resize", resize);
  resize();

  // Animation loop
  let t = 0;
  function animate(){
    t += 0.01;

    // gentle swirling cloud
    cloud.rotation.y += 0.0015;
    cloud.rotation.x = Math.sin(t*0.25)*0.05;

    // core breathing
    const breathe = 1 + Math.sin(t*1.2)*0.03;
    core.scale.set(breathe, breathe, breathe);
    core.rotation.y += 0.004;
    core.rotation.x += 0.002;

    // nodes subtle orbit wiggle
    nodes.forEach((n, idx)=>{
      n.position.y += Math.sin(t*0.9 + idx)*0.002;
    });

    // drift flicker
    driftGroup.children.forEach((l, i)=>{
      l.material.opacity = 0.25 + (driftIntensity*0.5) + Math.sin(t*2 + i)*0.08;
    });

    // anomaly pulse
    anomalyGroup.children.forEach((r)=>{
      const p = r.userData.pulse || 1.0;
      const s = 1 + Math.sin(t*3*p)*0.06*(0.4+anomalyIntensity);
      r.scale.set(s,s,s);
      r.material.opacity = 0.10 + anomalyIntensity*0.25 + Math.sin(t*2*p)*0.05;
    });

    renderer.render(scene, camera);
    requestAnimationFrame(animate);
  }
  animate();

  // -----------------------------
  // UI Actions (Preview)
  // -----------------------------
  function setView(mode){
    if(mode === "balanced"){
      driftIntensity = 0.65; anomalyIntensity = 0.55; calmness = 0.20;
      $("hudLine").textContent = "Balanced view: moderate drift beams and anomaly pulses.";
    } else if(mode === "drift"){
      driftIntensity = 0.92; anomalyIntensity = 0.48; calmness = 0.10;
      $("hudLine").textContent = "Drift focus: increased drift vectors (policy/config changes).";
    } else if(mode === "anomaly"){
      driftIntensity = 0.55; anomalyIntensity = 0.92; calmness = 0.10;
      $("hudLine").textContent = "Anomaly focus: stronger entropic/anomalous pulses.";
    } else if(mode === "quiet"){
      driftIntensity = 0.18; anomalyIntensity = 0.15; calmness = 0.85;
      $("hudLine").textContent = "Quiet mode: stabilized cloud posture (preview).";
    }
    rebuildDrift();
    rebuildAnomalies();
    updateStabilityKpi();
  }

  $("viewSelect").addEventListener("change", (e)=>{
    log(`View set: ${e.target.value}`);
    setView(e.target.value);
  });

  $("scanBtn").addEventListener("click", ()=>{
    log("Scan Cloud (preview): would ingest CloudTrail/Activity logs and refresh topology.");
    // Visual effect: quick pulse
    anomalyIntensity = Math.min(1, anomalyIntensity + 0.08);
    rebuildAnomalies(); updateStabilityKpi();
  });

  $("analyzeBtn").addEventListener("click", ()=>{
    log("Analyze Drift (preview): would compute drift vectors from IaC vs actual state.");
    driftIntensity = Math.min(1, driftIntensity + 0.08);
    rebuildDrift(); updateStabilityKpi();
  });

  $("stabilizeBtn").addEventListener("click", ()=>{
    log("Stabilize (preview): would propose guardrails + rollback plan; no changes executed.");
    calmness = Math.min(1, calmness + 0.25);
    driftIntensity = Math.max(0, driftIntensity - 0.18);
    anomalyIntensity = Math.max(0, anomalyIntensity - 0.15);
    rebuildDrift(); rebuildAnomalies(); updateStabilityKpi();
    alert("PREVIEW: Stabilization would\n• enforce policy baselines\n• restrict public exposure\n• rotate suspicious credentials\n• generate rollback plan\n\n(No live execution.)");
  });

  $("containBtn").addEventListener("click", ()=>{
    log("Contain High Risk (preview): would quarantine flagged identities; no changes executed.");
    driftIntensity = Math.max(0, driftIntensity - 0.10);
    anomalyIntensity = Math.max(0, anomalyIntensity - 0.10);
    rebuildDrift(); rebuildAnomalies(); updateStabilityKpi();
    alert("PREVIEW: Containment would\n• disable sign-in for HIGH-RISK identities\n• revoke sessions/tokens\n• remove elevated roles\n• open incident ticket\n\n(No live execution.)");
  });

  // Init
  log("3D Cloud preview initialized.");
  setView("balanced");
})();
</script>
</body>
</html>
from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import uuid

app = FastAPI(title="Real Cloud SOC Backend (Preview First)")

# Demo auth (replace with real auth/MFA)
ADMIN_TOKEN = "demo-admin-token"
MFA_CODE = "123456"

class Finding(BaseModel):
    id: str
    cloud: str               # aws | azure
    severity: str            # LOW | MED | HIGH
    kind: str                # drift | anomaly | exposure | identity
    target: str              # resource/identity display
    summary: str
    fix_preview: List[str]

class StabilityInputs(BaseModel):
    drift_score: float
    anomaly_score: float
    exposure_score: float
    identity_score: float

class Stability(BaseModel):
    stability_index: float
    inputs: StabilityInputs

class ScanRequest(BaseModel):
    mode: str = "preview"    # preview | execute (execute not used here)

class ScanResponse(BaseModel):
    scanned_at: str
    findings: List[Finding]
    stability: Stability

class PlanRequest(BaseModel):
    mode: str = "preview"    # preview

class PlanStep(BaseModel):
    step_id: str
    action: str              # e.g. "restrict_ingress", "enforce_mfa", "quarantine_identity"
    cloud: str
    target_id: str
    preview: bool
    rationale: str
    safety: List[str]

class PlanResponse(BaseModel):
    plan_id: str
    mode: str                # preview | execute
    created_at: str
    steps: List[PlanStep]
    applied_count: int = 0
    blocked_count: int = 0
    report: Dict[str, Any] = {}

class ExecuteRequest(BaseModel):
    plan_id: str
    justification: str

# ---- Helpers ----
def require_admin(x_admin_token: str, x_mfa: str):
    if x_admin_token != ADMIN_TOKEN or x_mfa != MFA_CODE:
        raise HTTPException(status_code=403, detail="Unauthorized (demo). Provide valid x-admin-token and x-mfa.")

def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()

# ---- Real connectors (replace stubs with SDK calls) ----
def collect_aws_signals() -> List[Finding]:
    # Replace with:
    # - CloudTrail lookup events
    # - AWS Config noncompliance
    # - Security Hub findings
    # - GuardDuty findings
    return [
        Finding(
            id="aws:finding:sg-ssh-open",
            cloud="aws",
            severity="HIGH",
            kind="exposure",
            target="SecurityGroup sg-1234",
            summary="Inbound SSH (22) open to 0.0.0.0/0",
            fix_preview=["Restrict ingress CIDR", "Prefer SSM Session Manager", "Add detective control (Config rule)"]
        ),
        Finding(
            id="aws:finding:iam-admin-attach",
            cloud="aws",
            severity="HIGH",
            kind="identity",
            target="User LegacyAdmin",
            summary="AdministratorAccess attached recently",
            fix_preview=["Detach admin policy", "Require MFA", "Quarantine identity (deny boundary)"]
        ),
    ]

def collect_azure_signals() -> List[Finding]:
    # Replace with:
    # - Azure Activity Logs
    # - Defender for Cloud recommendations/alerts
    # - Azure Policy noncompliance
    # - Entra ID risky sign-ins
    return [
        Finding(
            id="azure:finding:storage-public",
            cloud="azure",
            severity="MED",
            kind="exposure",
            target="Storage acct mystorage",
            summary="Public blob access enabled",
            fix_preview=["Disable public access", "Enforce private endpoints", "Apply Azure Policy deny"]
        ),
        Finding(
            id="azure:finding:nsg-rdp-broad",
            cloud="azure",
            severity="HIGH",
            kind="exposure",
            target="NSG nsg-prod",
            summary="RDP (3389) allowed from broad IP range",
            fix_preview=["Restrict source IP", "Use Bastion/JIT", "Enable Defender recommendations"]
        ),
    ]

def compute_stability(findings: List[Finding]) -> Stability:
    # Simple transparent “AI-style” index; replace with ML later.
    # Scores 0..100 where higher is worse; stability = 100 - weighted risk
    drift = sum(1 for f in findings if f.kind == "drift")
    anomaly = sum(1 for f in findings if f.kind == "anomaly")
    exposure = sum(1 for f in findings if f.kind == "exposure")
    identity = sum(1 for f in findings if f.kind == "identity")

    # severity weights
    sev_weight = {"LOW": 10, "MED": 25, "HIGH": 45}
    base = sum(sev_weight.get(f.severity, 20) for f in findings)

    # normalize-ish
    drift_score = min(100.0, drift * 18.0 + base * 0.15)
    anomaly_score = min(100.0, anomaly * 20.0 + base * 0.12)
    exposure_score = min(100.0, exposure * 22.0 + base * 0.10)
    identity_score = min(100.0, identity * 24.0 + base * 0.10)

    weighted_risk = (0.30*drift_score + 0.30*anomaly_score + 0.25*exposure_score + 0.15*identity_score)
    stability_index = max(0.0, min(100.0, 100.0 - weighted_risk))

    return Stability(
        stability_index=stability_index,
        inputs=StabilityInputs(
            drift_score=drift_score,
            anomaly_score=anomaly_score,
            exposure_score=exposure_score,
            identity_score=identity_score
        )
    )

# In-memory plan store for demo
PLANS: Dict[str, PlanResponse] = {}

@app.get("/health")
def health():
    return {"service": "Real Cloud SOC Backend (Preview First)", "time": now_utc()}

@app.post("/scan", response_model=ScanResponse)
def scan(req: ScanRequest, x_admin_token: str = Header(...), x_mfa: str = Header(...)):
    require_admin(x_admin_token, x_mfa)

    findings = []
    findings.extend(collect_aws_signals())
    findings.extend(collect_azure_signals())

    stability = compute_stability(findings)

    return ScanResponse(
        scanned_at=now_utc(),
        findings=findings,
        stability=stability
    )

@app.post("/plan", response_model=PlanResponse)
def plan(req: PlanRequest, x_admin_token: str = Header(...), x_mfa: str = Header(...)):
    require_admin(x_admin_token, x_mfa)

    # Build plan from current findings (preview)
    findings = collect_aws_signals() + collect_azure_signals()

    steps: List[PlanStep] = []
    for f in findings:
        action = "review"
        if f.kind == "exposure" and f.severity in ("MED", "HIGH"):
            action = "restrict_exposure"
        if f.kind == "identity" and f.severity == "HIGH":
            action = "quarantine_identity"
        if f.kind == "drift":
            action = "reconcile_iac"

        steps.append(PlanStep(
            step_id=str(uuid.uuid4()),
            action=action,
            cloud=f.cloud,
            target_id=f.id,
            preview=True,
            rationale=f"{f.severity} {f.kind}: {f.summary}",
            safety=[
                "Preview diff required",
                "Rollback plan required",
                "No deletion; containment first",
                "Audit log required"
            ]
        ))

    plan_id = str(uuid.uuid4())
    plan_obj = PlanResponse(
        plan_id=plan_id,
        mode="preview",
        created_at=now_utc(),
        steps=steps,
        report={"note": "Preview plan only. Execution is guarded and uses allowlisted actions."}
    )
    PLANS[plan_id] = plan_obj
    return plan_obj

@app.post("/execute", response_model=PlanResponse)
def execute(req: ExecuteRequest, x_admin_token: str = Header(...), x_mfa: str = Header(...)):
    require_admin(x_admin_token, x_mfa)

    if len(req.justification.strip()) < 10:
        raise HTTPException(status_code=400, detail="Justification too short.")

    plan_obj = PLANS.get(req.plan_id)
    if not plan_obj:
        raise HTTPException(status_code=404, detail="Plan not found. Build plan first.")

    # Guarded execution: we only “apply” allowlisted, safe actions here.
    # Replace with real SDK calls + robust scoping/allowlists.
    allowlisted = {"restrict_exposure", "quarantine_identity", "reconcile_iac"}

    applied = 0
    blocked = 0
    results: List[Dict[str, Any]] = []

    for step in plan_obj.steps:
        if step.action not in allowlisted:
            blocked += 1
            results.append({"step_id": step.step_id, "status": "blocked", "reason": "action not allowlisted"})
            continue

        # EXECUTION PLACEHOLDER:
        # - AWS restrict exposure -> update SG rules / S3 public access block
        # - AWS quarantine -> attach deny boundary / disable console login (careful)
        # - Azure restrict exposure -> NSG rules / storage public access off
        # - Azure quarantine -> disable sign-in / revoke tokens
        applied += 1
        results.append({"step_id": step.step_id, "status": "applied", "note": "demo apply (wire SDKs for real)"})

    executed = PlanResponse(
        plan_id=plan_obj.plan_id,
        mode="execute",
        created_at=plan_obj.created_at,
        steps=[PlanStep(**{**step.dict(), "preview": False}) for step in plan_obj.steps],
        applied_count=applied,
        blocked_count=blocked,
        report={
            "executed_at": now_utc(),
            "justification": req.justification,
            "results": results,
            "warning": "Execution is demo-mode placeholders unless you wire real AWS/Azure SDK calls with scoping/allowlists."
        }
    )
    PLANS[req.plan_id] = executed
    return executed
pip install fastapi uvicorn
uvicorn soc_backend:app --reload --port 8080
// soc_backend_express.js
const express = require("express");
const app = express();
app.use(express.json());

const ADMIN_TOKEN = "demo-admin-token";
const MFA_CODE = "123456";

function requireAdmin(req, res, next){
  if(req.headers["x-admin-token"] !== ADMIN_TOKEN || req.headers["x-mfa"] !== MFA_CODE){
    return res.status(403).json({ error: "Unauthorized (demo)" });
  }
  next();
}

app.get("/health", (req,res)=> res.json({ service:"Real Cloud SOC Backend (Express)", time:new Date().toISOString() }));

app.post("/scan", requireAdmin, (req,res)=>{
  // TODO: replace with real AWS/Azure collectors
  res.json({
    scanned_at: new Date().toISOString(),
    findings: [],
    stability: { stability_index: 100, inputs:{ drift_score:0, anomaly_score:0, exposure_score:0, identity_score:0 } }
  });
});

app.post("/plan", requireAdmin, (req,res)=>{
  res.json({ plan_id:"demo", mode:"preview", created_at:new Date().toISOString(), steps:[], report:{ note:"stub" } });
});

app.post("/execute", requireAdmin, (req,res)=>{
  res.json({ plan_id:req.body.plan_id, mode:"execute", created_at:new Date().toISOString(), steps:[], applied_count:0, blocked_count:0, report:{ note:"stub" } });
});

app.listen(8080, ()=> console.log("SOC Express backend on :8080"));
diff --git a/cloud_stabilizer.py b/cloud_stabilizer.py
new file mode 100644
index 0000000000000000000000000000000000000000..a239a206a14afd97bf4fafabff372913c1343943
--- /dev/null
+++ b/cloud_stabilizer.py
@@ -0,0 +1,140 @@
+"""Cloud stabilization and threat-mitigation utilities.
+
+This module provides defensive controls for keeping cloud workloads stable
+while identifying and isolating malicious activity and users.
+"""
+
+from __future__ import annotations
+
+from dataclasses import dataclass, field
+from statistics import mean
+from typing import Iterable
+
+
+@dataclass(frozen=True)
+class ActivityEvent:
+    """Single activity event observed in the cloud control plane."""
+
+    user_id: str
+    action: str
+    source_ip: str
+    risk_score: float = 0.0
+    failed_auth_count: int = 0
+    requests_per_minute: int = 0
+
+
+@dataclass
+class CloudState:
+    """Cloud health and configuration snapshot."""
+
+    cpu_usage_percent: float
+    memory_usage_percent: float
+    error_rate_percent: float
+    active_instances: int
+    min_instances: int = 2
+    max_instances: int = 50
+
+
+@dataclass
+class StabilizationPolicy:
+    """Policy tuning for stabilization and threat response."""
+
+    cpu_target_percent: float = 65.0
+    memory_target_percent: float = 70.0
+    high_error_rate_percent: float = 3.0
+    malicious_risk_threshold: float = 0.8
+    max_failed_auth: int = 6
+    max_requests_per_minute: int = 600
+    suspicious_actions: tuple[str, ...] = (
+        "disable_audit_logging",
+        "create_root_key",
+        "privilege_escalation",
+        "delete_backups",
+        "exfiltrate_data",
+    )
+
+
+@dataclass
+class StabilizationReport:
+    """Structured output with stabilization and security actions."""
+
+    recommended_instance_count: int
+    blocked_users: list[str] = field(default_factory=list)
+    quarantined_events: list[ActivityEvent] = field(default_factory=list)
+    applied_controls: list[str] = field(default_factory=list)
+
+
+class CloudStabilizer:
+    """Defensive cloud stabilizer with malicious activity isolation."""
+
+    def __init__(self, policy: StabilizationPolicy | None = None):
+        self.policy = policy or StabilizationPolicy()
+
+    def stabilize(self, state: CloudState, events: Iterable[ActivityEvent]) -> StabilizationReport:
+        """Produce a full stabilization plan for performance and security."""
+        events = list(events)
+        quarantined_events = self._detect_malicious_events(events)
+        blocked_users = sorted({event.user_id for event in quarantined_events})
+
+        recommended_instances = self._recommend_instance_count(state)
+        controls = self._recommended_controls(state, blocked_users, quarantined_events)
+
+        return StabilizationReport(
+            recommended_instance_count=recommended_instances,
+            blocked_users=blocked_users,
+            quarantined_events=quarantined_events,
+            applied_controls=controls,
+        )
+
+    def _recommend_instance_count(self, state: CloudState) -> int:
+        """Autoscaling recommendation to maintain reliable workload stability."""
+        utilization_pressure = mean([
+            state.cpu_usage_percent / max(self.policy.cpu_target_percent, 1),
+            state.memory_usage_percent / max(self.policy.memory_target_percent, 1),
+        ])
+
+        if state.error_rate_percent > self.policy.high_error_rate_percent:
+            utilization_pressure += 0.3
+
+        recommended = round(state.active_instances * utilization_pressure)
+        recommended = max(state.min_instances, recommended)
+        recommended = min(state.max_instances, recommended)
+        return recommended
+
+    def _detect_malicious_events(self, events: list[ActivityEvent]) -> list[ActivityEvent]:
+        """Identify events that should be quarantined and users blocked."""
+        malicious_events: list[ActivityEvent] = []
+
+        for event in events:
+            suspicious_action = event.action.lower() in self.policy.suspicious_actions
+            high_risk = event.risk_score >= self.policy.malicious_risk_threshold
+            brute_force_pattern = event.failed_auth_count >= self.policy.max_failed_auth
+            flood_pattern = event.requests_per_minute >= self.policy.max_requests_per_minute
+
+            if suspicious_action or high_risk or brute_force_pattern or flood_pattern:
+                malicious_events.append(event)
+
+        return malicious_events
+
+    def _recommended_controls(
+        self,
+        state: CloudState,
+        blocked_users: list[str],
+        quarantined_events: list[ActivityEvent],
+    ) -> list[str]:
+        controls = [
+            "enable_waf_strict_mode",
+            "enforce_mfa_for_all_users",
+            "rotate_secrets_and_access_keys",
+        ]
+
+        if state.error_rate_percent > self.policy.high_error_rate_percent:
+            controls.append("route_traffic_to_healthy_region")
+
+        if blocked_users:
+            controls.append("disable_blocked_users_and_revoke_sessions")
+
+        if quarantined_events:
+            controls.append("open_security_incident_and_preserve_forensics")
+
+        return controls
diff --git a/cloud_stabilizer.py b/cloud_stabilizer.py
new file mode 100644
index 0000000000000000000000000000000000000000..bb19d5107746f0fa45d42118a4eac8b1f18d6007
--- /dev/null
+++ b/cloud_stabilizer.py
@@ -0,0 +1,162 @@
+"""Cloud stabilization and threat-removal utilities.
+
+The module focuses on two goals:
+1. Stabilize cloud nodes when health degrades.
+2. Remove malicious activities and malicious users from the environment.
+"""
+
+from __future__ import annotations
+
+from dataclasses import dataclass, field
+from typing import Dict, List, Set
+
+
+@dataclass(frozen=True)
+class CloudNode:
+    """A single compute or service node in the cloud."""
+
+    node_id: str
+    cpu_load: float  # 0.0 .. 1.0
+    memory_load: float  # 0.0 .. 1.0
+    error_rate: float  # 0.0 .. 1.0
+
+
+@dataclass(frozen=True)
+class Activity:
+    """A user-initiated activity/event in the cloud."""
+
+    activity_id: str
+    user_id: str
+    source_ip: str
+    action: str
+    request_rate_per_minute: int
+    anomaly_score: float  # 0.0 .. 1.0
+
+
+@dataclass
+class CloudState:
+    """Mutable cloud state that a stabilizer can repair."""
+
+    nodes: List[CloudNode] = field(default_factory=list)
+    activities: List[Activity] = field(default_factory=list)
+    active_users: Set[str] = field(default_factory=set)
+
+
+@dataclass(frozen=True)
+class StabilizationReport:
+    """Summary of all actions performed in a stabilization run."""
+
+    stability_score: float
+    overloaded_nodes: List[str]
+    terminated_activities: List[str]
+    removed_users: List[str]
+    remediations: List[str]
+
+
+class CloudStabilizer:
+    """Stabilizes nodes and eliminates malicious behavior/users."""
+
+    def __init__(
+        self,
+        max_safe_cpu_load: float = 0.85,
+        max_safe_memory_load: float = 0.90,
+        max_safe_error_rate: float = 0.10,
+        malicious_anomaly_threshold: float = 0.80,
+        malicious_request_rate_threshold: int = 300,
+    ) -> None:
+        self.max_safe_cpu_load = max_safe_cpu_load
+        self.max_safe_memory_load = max_safe_memory_load
+        self.max_safe_error_rate = max_safe_error_rate
+        self.malicious_anomaly_threshold = malicious_anomaly_threshold
+        self.malicious_request_rate_threshold = malicious_request_rate_threshold
+
+    def stabilize(self, state: CloudState) -> StabilizationReport:
+        """Run one complete stabilization cycle over the current cloud state."""
+        overloaded_nodes = self._find_unstable_nodes(state.nodes)
+        terminated_activities, malicious_users = self._remove_malicious_traffic(state)
+        remediations = self._remediate_nodes(overloaded_nodes)
+        removed_users = self._remove_users(state, malicious_users)
+
+        stability_score = self._compute_stability_score(state)
+
+        return StabilizationReport(
+            stability_score=stability_score,
+            overloaded_nodes=[node.node_id for node in overloaded_nodes],
+            terminated_activities=terminated_activities,
+            removed_users=removed_users,
+            remediations=remediations,
+        )
+
+    def _find_unstable_nodes(self, nodes: List[CloudNode]) -> List[CloudNode]:
+        unstable = []
+        for node in nodes:
+            if (
+                node.cpu_load > self.max_safe_cpu_load
+                or node.memory_load > self.max_safe_memory_load
+                or node.error_rate > self.max_safe_error_rate
+            ):
+                unstable.append(node)
+        return unstable
+
+    def _remove_malicious_traffic(self, state: CloudState) -> tuple[List[str], Set[str]]:
+        safe_activities: List[Activity] = []
+        terminated: List[str] = []
+        malicious_users: Set[str] = set()
+
+        for activity in state.activities:
+            if self._is_malicious_activity(activity):
+                terminated.append(activity.activity_id)
+                malicious_users.add(activity.user_id)
+            else:
+                safe_activities.append(activity)
+
+        state.activities = safe_activities
+        return terminated, malicious_users
+
+    def _is_malicious_activity(self, activity: Activity) -> bool:
+        return (
+            activity.anomaly_score >= self.malicious_anomaly_threshold
+            or activity.request_rate_per_minute >= self.malicious_request_rate_threshold
+            or activity.action.lower() in {"credential_stuffing", "privilege_escalation", "ransomware"}
+        )
+
+    def _remove_users(self, state: CloudState, malicious_users: Set[str]) -> List[str]:
+        removed = sorted(user_id for user_id in malicious_users if user_id in state.active_users)
+        state.active_users.difference_update(malicious_users)
+        return removed
+
+    def _remediate_nodes(self, overloaded_nodes: List[CloudNode]) -> List[str]:
+        remediations = []
+        for node in overloaded_nodes:
+            remediations.extend(
+                [
+                    f"node:{node.node_id}:autoscale_out",
+                    f"node:{node.node_id}:rate_limit_noncritical_workloads",
+                    f"node:{node.node_id}:restart_unhealthy_services",
+                ]
+            )
+        return remediations
+
+    def _compute_stability_score(self, state: CloudState) -> float:
+        if not state.nodes:
+            return 1.0
+
+        score_sum = 0.0
+        for node in state.nodes:
+            # Convert load/error into a quality score (higher is better).
+            node_score = 1.0 - ((node.cpu_load + node.memory_load + node.error_rate) / 3.0)
+            score_sum += max(0.0, node_score)
+        return round(score_sum / len(state.nodes), 4)
+
+
+def stabilize_cloud_completely(state: CloudState) -> Dict[str, object]:
+    """High-level helper to fully stabilize cloud state and purge malicious actors."""
+    stabilizer = CloudStabilizer()
+    report = stabilizer.stabilize(state)
+    return {
+        "stability_score": report.stability_score,
+        "overloaded_nodes": report.overloaded_nodes,
+        "terminated_activities": report.terminated_activities,
+        "removed_users": report.removed_users,
+        "remediations": report.remediations,
+    }
diff --git a/tests/test_cloud_stabilizer.py b/tests/test_cloud_stabilizer.py
new file mode 100644
index 0000000000000000000000000000000000000000..2a1a4cb5c8b8dd82480e8dbb4b6e688304040865
--- /dev/null
+++ b/tests/test_cloud_stabilizer.py
@@ -0,0 +1,57 @@
+import unittest
+
+from cloud_stabilizer import Activity, CloudNode, CloudState, stabilize_cloud_completely
+
+
+class CloudStabilizerTests(unittest.TestCase):
+    def test_stabilizer_terminates_malicious_activity_and_removes_user(self):
+        state = CloudState(
+            nodes=[
+                CloudNode("node-a", cpu_load=0.92, memory_load=0.91, error_rate=0.02),
+                CloudNode("node-b", cpu_load=0.35, memory_load=0.40, error_rate=0.01),
+            ],
+            activities=[
+                Activity(
+                    activity_id="act-safe",
+                    user_id="alice",
+                    source_ip="10.0.0.10",
+                    action="read",
+                    request_rate_per_minute=25,
+                    anomaly_score=0.1,
+                ),
+                Activity(
+                    activity_id="act-malicious",
+                    user_id="eve",
+                    source_ip="10.0.0.66",
+                    action="credential_stuffing",
+                    request_rate_per_minute=1200,
+                    anomaly_score=0.95,
+                ),
+            ],
+            active_users={"alice", "eve"},
+        )
+
+        report = stabilize_cloud_completely(state)
+
+        self.assertIn("act-malicious", report["terminated_activities"])
+        self.assertIn("eve", report["removed_users"])
+        self.assertIn("node-a", report["overloaded_nodes"])
+        self.assertTrue(any("autoscale_out" in item for item in report["remediations"]))
+
+        self.assertEqual({"alice"}, state.active_users)
+        self.assertEqual(["act-safe"], [a.activity_id for a in state.activities])
+
+    def test_stability_score_bounds(self):
+        state = CloudState(
+            nodes=[CloudNode("node-good", cpu_load=0.1, memory_load=0.1, error_rate=0.0)],
+            activities=[],
+            active_users=set(),
+        )
+
+        report = stabilize_cloud_completely(state)
+        self.assertGreaterEqual(report["stability_score"], 0.0)
+        self.assertLessEqual(report["stability_score"], 1.0)
+
+
+if __name__ == "__main__":
+    unittest.main()
diff --git a/cloud_stabilizer.py b/cloud_stabilizer.py
new file mode 100644
index 0000000000000000000000000000000000000000..a239a206a14afd97bf4fafabff372913c1343943
--- /dev/null
+++ b/cloud_stabilizer.py
@@ -0,0 +1,140 @@
+"""Cloud stabilization and threat-mitigation utilities.
+
+This module provides defensive controls for keeping cloud workloads stable
+while identifying and isolating malicious activity and users.
+"""
+
+from __future__ import annotations
+
+from dataclasses import dataclass, field
+from statistics import mean
+from typing import Iterable
+
+
+@dataclass(frozen=True)
+class ActivityEvent:
+    """Single activity event observed in the cloud control plane."""
+
+    user_id: str
+    action: str
+    source_ip: str
+    risk_score: float = 0.0
+    failed_auth_count: int = 0
+    requests_per_minute: int = 0
+
+
+@dataclass
+class CloudState:
+    """Cloud health and configuration snapshot."""
+
+    cpu_usage_percent: float
+    memory_usage_percent: float
+    error_rate_percent: float
+    active_instances: int
+    min_instances: int = 2
+    max_instances: int = 50
+
+
+@dataclass
+class StabilizationPolicy:
+    """Policy tuning for stabilization and threat response."""
+
+    cpu_target_percent: float = 65.0
+    memory_target_percent: float = 70.0
+    high_error_rate_percent: float = 3.0
+    malicious_risk_threshold: float = 0.8
+    max_failed_auth: int = 6
+    max_requests_per_minute: int = 600
+    suspicious_actions: tuple[str, ...] = (
+        "disable_audit_logging",
+        "create_root_key",
+        "privilege_escalation",
+        "delete_backups",
+        "exfiltrate_data",
+    )
+
+
+@dataclass
+class StabilizationReport:
+    """Structured output with stabilization and security actions."""
+
+    recommended_instance_count: int
+    blocked_users: list[str] = field(default_factory=list)
+    quarantined_events: list[ActivityEvent] = field(default_factory=list)
+    applied_controls: list[str] = field(default_factory=list)
+
+
+class CloudStabilizer:
+    """Defensive cloud stabilizer with malicious activity isolation."""
+
+    def __init__(self, policy: StabilizationPolicy | None = None):
+        self.policy = policy or StabilizationPolicy()
+
+    def stabilize(self, state: CloudState, events: Iterable[ActivityEvent]) -> StabilizationReport:
+        """Produce a full stabilization plan for performance and security."""
+        events = list(events)
+        quarantined_events = self._detect_malicious_events(events)
+        blocked_users = sorted({event.user_id for event in quarantined_events})
+
+        recommended_instances = self._recommend_instance_count(state)
+        controls = self._recommended_controls(state, blocked_users, quarantined_events)
+
+        return StabilizationReport(
+            recommended_instance_count=recommended_instances,
+            blocked_users=blocked_users,
+            quarantined_events=quarantined_events,
+            applied_controls=controls,
+        )
+
+    def _recommend_instance_count(self, state: CloudState) -> int:
+        """Autoscaling recommendation to maintain reliable workload stability."""
+        utilization_pressure = mean([
+            state.cpu_usage_percent / max(self.policy.cpu_target_percent, 1),
+            state.memory_usage_percent / max(self.policy.memory_target_percent, 1),
+        ])
+
+        if state.error_rate_percent > self.policy.high_error_rate_percent:
+            utilization_pressure += 0.3
+
+        recommended = round(state.active_instances * utilization_pressure)
+        recommended = max(state.min_instances, recommended)
+        recommended = min(state.max_instances, recommended)
+        return recommended
+
+    def _detect_malicious_events(self, events: list[ActivityEvent]) -> list[ActivityEvent]:
+        """Identify events that should be quarantined and users blocked."""
+        malicious_events: list[ActivityEvent] = []
+
+        for event in events:
+            suspicious_action = event.action.lower() in self.policy.suspicious_actions
+            high_risk = event.risk_score >= self.policy.malicious_risk_threshold
+            brute_force_pattern = event.failed_auth_count >= self.policy.max_failed_auth
+            flood_pattern = event.requests_per_minute >= self.policy.max_requests_per_minute
+
+            if suspicious_action or high_risk or brute_force_pattern or flood_pattern:
+                malicious_events.append(event)
+
+        return malicious_events
+
+    def _recommended_controls(
+        self,
+        state: CloudState,
+        blocked_users: list[str],
+        quarantined_events: list[ActivityEvent],
+    ) -> list[str]:
+        controls = [
+            "enable_waf_strict_mode",
+            "enforce_mfa_for_all_users",
+            "rotate_secrets_and_access_keys",
+        ]
+
+        if state.error_rate_percent > self.policy.high_error_rate_percent:
+            controls.append("route_traffic_to_healthy_region")
+
+        if blocked_users:
+            controls.append("disable_blocked_users_and_revoke_sessions")
+
+        if quarantined_events:
+            controls.append("open_security_incident_and_preserve_forensics")
+
+        return controls
diff --git a/cloud_stabilizer.py b/cloud_stabilizer.py
new file mode 100644
index 0000000000000000000000000000000000000000..bda1896183942c77656bb8d983ff7d420c901f8c
--- /dev/null
+++ b/cloud_stabilizer.py
@@ -0,0 +1,154 @@
+"""Cloud stabilization and threat-removal engine.
+
+This module provides a deterministic policy layer that can be wired into
+infrastructure automation. It focuses on two guarantees:
+
+1. Keep service health stable by responding to overload and unhealthy nodes.
+2. Remove malicious activity by suspending risky users and quarantining assets.
+"""
+
+from __future__ import annotations
+
+from dataclasses import dataclass, field
+from enum import Enum
+from typing import Dict, List, Sequence
+
+
+class UserStatus(str, Enum):
+    """Normalized user account states."""
+
+    ACTIVE = "active"
+    SUSPENDED = "suspended"
+
+
+@dataclass
+class User:
+    """Identity record used for threat decisions."""
+
+    user_id: str
+    failed_logins: int = 0
+    reports: int = 0
+    known_bad_ip_hits: int = 0
+    privileged_actions_per_hour: int = 0
+    status: UserStatus = UserStatus.ACTIVE
+
+
+@dataclass
+class ServiceNode:
+    """Simplified cloud service instance."""
+
+    node_id: str
+    cpu_percent: float
+    memory_percent: float
+    error_rate_percent: float
+    quarantined: bool = False
+
+
+@dataclass
+class CloudState:
+    """Current view of cloud users + service nodes."""
+
+    users: Dict[str, User] = field(default_factory=dict)
+    nodes: Dict[str, ServiceNode] = field(default_factory=dict)
+
+
+@dataclass
+class Action:
+    """Audit log entry describing actions taken."""
+
+    action_type: str
+    target_id: str
+    reason: str
+
+
+class CloudStabilizer:
+    """Rule-based stabilizer for operational resilience and abuse prevention."""
+
+    # Operational thresholds
+    MAX_CPU = 85.0
+    MAX_MEMORY = 90.0
+    MAX_ERROR_RATE = 5.0
+
+    # Risk scoring thresholds
+    SUSPEND_USER_SCORE = 70
+
+    def __init__(self) -> None:
+        self.actions: List[Action] = []
+
+    def stabilize(self, cloud: CloudState) -> List[Action]:
+        """Evaluate cloud state and apply stabilizing/remediation actions."""
+        self.actions = []
+        self._remove_malicious_users(cloud)
+        self._stabilize_nodes(cloud)
+        return self.actions
+
+    def _remove_malicious_users(self, cloud: CloudState) -> None:
+        for user in cloud.users.values():
+            if user.status == UserStatus.SUSPENDED:
+                continue
+
+            risk = self._risk_score(user)
+            if risk >= self.SUSPEND_USER_SCORE:
+                user.status = UserStatus.SUSPENDED
+                self.actions.append(
+                    Action(
+                        action_type="suspend_user",
+                        target_id=user.user_id,
+                        reason=f"risk_score={risk}",
+                    )
+                )
+
+    @staticmethod
+    def _risk_score(user: User) -> int:
+        """Compute a deterministic abuse score."""
+        score = 0
+        score += min(user.failed_logins * 5, 30)
+        score += min(user.reports * 10, 30)
+        score += min(user.known_bad_ip_hits * 20, 40)
+        score += min(user.privileged_actions_per_hour * 2, 20)
+        return min(score, 100)
+
+    def _stabilize_nodes(self, cloud: CloudState) -> None:
+        """Quarantine unhealthy nodes to protect service stability."""
+        for node in cloud.nodes.values():
+            if node.quarantined:
+                continue
+
+            overload = node.cpu_percent > self.MAX_CPU or node.memory_percent > self.MAX_MEMORY
+            erroring = node.error_rate_percent > self.MAX_ERROR_RATE
+
+            if overload or erroring:
+                node.quarantined = True
+                reason = self._node_reason(node, overload, erroring)
+                self.actions.append(
+                    Action(
+                        action_type="quarantine_node",
+                        target_id=node.node_id,
+                        reason=reason,
+                    )
+                )
+
+    @staticmethod
+    def _node_reason(node: ServiceNode, overload: bool, erroring: bool) -> str:
+        reasons: List[str] = []
+        if overload:
+            reasons.append(
+                f"overload(cpu={node.cpu_percent:.1f}%, memory={node.memory_percent:.1f}%)"
+            )
+        if erroring:
+            reasons.append(f"high_error_rate({node.error_rate_percent:.2f}%)")
+        return "; ".join(reasons)
+
+
+def stabilize_cloud(
+    users: Sequence[User],
+    nodes: Sequence[ServiceNode],
+) -> tuple[CloudState, List[Action]]:
+    """Convenience API for one-shot stabilization runs."""
+    state = CloudState(
+        users={user.user_id: user for user in users},
+        nodes={node.node_id: node for node in nodes},
+    )
+    stabilizer = CloudStabilizer()
+    actions = stabilizer.stabilize(state)
+    return state, actions
npm init -y
npm i express axios
const express = require("express");
const axios = require("axios");
const crypto = require("crypto");

const app = express();
app.use(express.json());

const {
  AZ_TENANT_ID,
  AZ_CLIENT_ID,
  AZ_CLIENT_SECRET,
  LA_WORKSPACE_ID
} = process.env;

function requireEnv() {
  const missing = ["AZ_TENANT_ID","AZ_CLIENT_ID","AZ_CLIENT_SECRET","LA_WORKSPACE_ID"].filter(k => !process.env[k]);
  if (missing.length) {
    throw new Error(`Missing env vars: ${missing.join(", ")}`);
  }
}

async function getToken() {
  const url = `https://login.microsoftonline.com/${AZ_TENANT_ID}/oauth2/v2.0/token`;
  const body = new URLSearchParams({
    client_id: AZ_CLIENT_ID,
    client_secret: AZ_CLIENT_SECRET,
    grant_type: "client_credentials",
    scope: "https://api.loganalytics.io/.default"
  });
  const res = await axios.post(url, body.toString(), {
    headers: { "Content-Type": "application/x-www-form-urlencoded" }
  });
  return res.data.access_token;
}

async function runKql(kql, timespan = "PT1H") {
  const token = await getToken();
  const url = `https://api.loganalytics.io/v1/workspaces/${LA_WORKSPACE_ID}/query`;
  const res = await axios.post(url, { query: kql, timespan }, {
    headers: { Authorization: `Bearer ${token}` }
  });
  return res.data;
}

function tableCount(resp) {
  const t = resp?.tables?.[0];
  if (!t || !t.rows) return 0;
  // if query returns a single row with count_ column, read it
  if (t.rows.length === 1 && t.columns?.some(c => c.name.toLowerCase().includes("count"))) {
    const idx = t.columns.findIndex(c => c.name.toLowerCase().includes("count"));
    return Number(t.rows[0][idx] || 0);
  }
  return t.rows.length;
}

// --- KQL signal pack (you can extend these safely) ---
const SIGNALS = [
  {
    query_tag: "signin_risky",
    kind: "identity",
    name: "Risky sign-ins (Entra ID)",
    timespan: "PT6H",
    kql: `
SigninLogs
| where TimeGenerated > ago(6h)
| summarize count()`
    ,
    fix_preview: [
      "Require MFA / Conditional Access for risky users",
      "Review impossible travel / unfamiliar sign-in properties",
      "Revoke refresh tokens for confirmed compromised accounts"
    ]
  },
  {
    query_tag: "azure_exposure_nsg",
    kind: "exposure",
    name: "Public exposure changes (AzureActivity NSG/Network)",
    timespan: "P1D",
    kql: `
AzureActivity
| where TimeGenerated > ago(1d)
| where OperationNameValue has_any ("Microsoft.Network/networkSecurityGroups/securityRules/write",
                                 "Microsoft.Network/networkSecurityGroups/write",
                                 "Microsoft.Network/publicIPAddresses/write",
                                 "Microsoft.Network/loadBalancers/write")
| summarize count()`
    ,
    fix_preview: [
      "Apply Azure Policy deny for 0.0.0.0/0 inbound where not approved",
      "Enable JIT access / Bastion",
      "Baseline NSG rules and alert on drift"
    ]
  },
  {
    query_tag: "aws_cloudtrail_ingested",
    kind: "drift",
    name: "AWS control-plane changes (if CloudTrail is ingested into Sentinel)",
    timespan: "P1D",
    // You must adjust table name depending on connector:
    // Common patterns: AWSCloudTrail, AWSCloudTrail_CL, or custom tables.
    kql: `
AWSCloudTrail
| where TimeGenerated > ago(1d)
| where EventName has_any ("PutBucketPolicy","AuthorizeSecurityGroupIngress","AttachUserPolicy","CreateAccessKey")
| summarize count()`
    ,
    fix_preview: [
      "Enforce SCP guardrails (deny public S3 policies, deny wide-open SG ingress)",
      "Rotate compromised access keys",
      "Route high-risk events to Sentinel incidents"
    ]
  },
  {
    query_tag: "anomaly_entropy_outliers",
    kind: "anomaly",
    name: "Entropy outlier findings (if you publish them into Log Analytics)",
    timespan: "P1D",
    // If you used the earlier publisher with log type EntropyFindings => EntropyFindings_CL
    kql: `
EntropyFindings_CL
| where TimeGenerated > ago(1d)
| summarize count()`
    ,
    fix_preview: [
      "Secret rotation and incident response for repeated fingerprints",
      "Block exfil pathways and add DLP/secret scanning",
      "Quarantine identities observed around the finding time window"
    ]
  }
];

function severityFromCount(kind, count) {
  // Conservative, tunable heuristics
  if (count >= 200) return "HIGH";
  if (count >= 50) return "MED";
  if (count > 0) return "LOW";
  // If zero, keep LOW but not noisy
  return "LOW";
}

function stabilityIndex(signals) {
  // 0..100 where higher is better
  // Convert counts to risk points with weights by kind
  const weights = { drift: 0.30, anomaly: 0.30, identity: 0.20, exposure: 0.20 };
  const buckets = { drift: 0, anomaly: 0, identity: 0, exposure: 0 };

  for (const s of signals) {
    // squash counts to 0..100 risk
    const risk = Math.min(100, Math.log10(1 + s.count) * 40);
    buckets[s.kind] += risk;
  }

  // normalize buckets roughly
  for (const k of Object.keys(buckets)) buckets[k] = Math.min(100, buckets[k]);

  const weighted = buckets.drift*weights.drift + buckets.anomaly*weights.anomaly +
                   buckets.identity*weights.identity + buckets.exposure*weights.exposure;

  const stability = Math.max(0, Math.min(100, 100 - weighted));
  return { stability_index: stability, inputs: buckets };
}

app.post("/scan", async (req, res) => {
  try {
    requireEnv();
    const mode = req.body?.mode || "preview";

    const out = [];
    for (const s of SIGNALS) {
      let count = 0;
      try {
        const resp = await runKql(s.kql, s.timespan);
        count = tableCount(resp);
      } catch (e) {
        // If a table doesn't exist (e.g., AWS not connected), report as unavailable
        out.push({
          ...s,
          count: 0,
          severity: "LOW",
          error: "Query failed (missing table/connector or permissions).",
        });
        continue;
      }

      out.push({
        query_tag: s.query_tag,
        kind: s.kind,
        name: s.name,
        count,
        severity: severityFromCount(s.kind, count),
        fix_preview: s.fix_preview
      });
    }

    const stability = stabilityIndex(out);

    res.json({
      mode,
      scanned_at: new Date().toISOString(),
      signals: out,
      stability
    });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.post("/plan", async (req, res) => {
  try {
    requireEnv();
    const plan_id = crypto.randomUUID();
    // In a real build: re-use scan outputs + enrich with entity/resource IDs from KQL results
    // Here we create a safe preview plan.
    const steps = [
      {
        step_id: crypto.randomUUID(),
        action: "tighten_exposure_guardrails",
        preview: true,
        rationale: "Reduce public exposure drift (NSG/Ingress changes).",
        safety: ["Azure Policy deny with exemptions", "Change windows", "Rollback documented"]
      },
      {
        step_id: crypto.randomUUID(),
        action: "identity_hardening",
        preview: true,
        rationale: "Reduce identity anomalies (risky sign-ins).",
        safety: ["Conditional Access staged rollout", "Break-glass accounts protected", "Audit trail"]
      },
      {
        step_id: crypto.randomUUID(),
        action: "entropy_indicator_response",
        preview: true,
        rationale: "Respond to entropy outlier indicators (possible leaked secrets).",
        safety: ["Rotate credentials", "Invalidate tokens", "Preserve evidence", "No deletion"]
      }
    ];

    res.json({
      plan_id,
      mode: "preview",
      created_at: new Date().toISOString(),
      steps
    });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.post("/execute", async (req, res) => {
  try {
    requireEnv();
    const { plan_id, justification, mode } = req.body || {};
    if (!plan_id) throw new Error("plan_id required");
    if (!justification || justification.trim().length < 10) throw new Error("justification required (10+ chars)");

    // Guarded execution placeholder:
    // In production, execution should call:
    // - Sentinel automation playbooks (Logic Apps) with parameters
    // - Azure Policy assignments / exemptions via ARM
    // - Conditional Access changes via Graph (staged)
    // - AWS guardrails via Organizations SCP / Config rules (if multi-cloud)
    //
    // Here, we return a report only.
    res.json({
      plan_id,
      mode: mode || "execute",
      applied_count: 0,
      blocked_count: 0,
      report: {
        note: "Execution is intentionally preview-only by default. Wire playbooks/policies with allowlists + approvals to apply changes.",
        justification,
        next_actions: [
          "Connect Sentinel playbooks for containment (disable user, revoke sessions, isolate VM) with approvals",
          "Enable/verify Azure Policy baselines + initiative assignments",
          "Ensure AWS connector tables exist if managing AWS through Sentinel"
        ]
      }
    });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.listen(8080, () => console.log("Sentinel SOC backend listening on http://localhost:8080"));
export AZ_TENANT_ID="..."
export AZ_CLIENT_ID="..."
export AZ_CLIENT_SECRET="..."
export LA_WORKSPACE_ID="..."

node sentinel_backend.js
// --- Add near the top with SIGNALS ---
const TIMESPACE_QUERIES = {
  // Time bins: anomaly events over time (SigninLogs)
  signin_time_series: (bin) => `
SigninLogs
| where TimeGenerated > ago(24h)
| summarize count() by bin(TimeGenerated, ${bin})
| order by TimeGenerated asc`,

  // Space: top sign-in countries (or locations) over the same window
  signin_space_hotspots: `
SigninLogs
| where TimeGenerated > ago(24h)
| summarize count() by tostring(LocationDetails.countryOrRegion)
| top 15 by count_ desc`,

  // Space: Azure drift hotspots by region (AzureActivity)
  azure_drift_space_by_region: `
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue has_any (
  "Microsoft.Network/networkSecurityGroups/securityRules/write",
  "Microsoft.Network/publicIPAddresses/write",
  "Microsoft.Authorization/policyAssignments/write",
  "Microsoft.Authorization/policyDefinitions/write"
)
| summarize count() by tostring(ResourceProviderValue), tostring(Location)
| top 15 by count_ desc`,

  // Time: Azure drift rate over time
  azure_drift_time_series: (bin) => `
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue has_any (
  "Microsoft.Network/networkSecurityGroups/securityRules/write",
  "Microsoft.Network/publicIPAddresses/write",
  "Microsoft.Authorization/policyAssignments/write",
  "Microsoft.Authorization/policyDefinitions/write"
)
| summarize count() by bin(TimeGenerated, ${bin})
| order by TimeGenerated asc`,

  // “Time-Space vector” approximation:
  // We model vectors as high-volume operations grouped by (ResourceId, Location) with first/last timestamps.
  drift_vectors: `
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue has_any (
  "Microsoft.Network/networkSecurityGroups/securityRules/write",
  "Microsoft.Network/publicIPAddresses/write",
  "Microsoft.Authorization/policyAssignments/write"
)
| summarize first_seen=min(TimeGenerated), last_seen=max(TimeGenerated), ops=count()
  by tostring(ResourceId), tostring(Location), tostring(OperationNameValue)
| top 20 by ops desc`
};

// --- Add this endpoint (requires runKql helper from earlier backend) ---
app.post("/timespace", async (req, res) => {
  try {
    requireEnv();
    const mode = req.body?.mode || "preview";
    const bin = req.body?.bin || "15m"; // 5m, 15m, 1h etc.
    const timespan = req.body?.timespan || "P1D"; // 24h default

    // Note: the KQL above uses ago(24h). If you prefer timespan param instead,
    // remove ago() clauses and rely on timespan argument in runKql.
    const [
      signinSeries, signinSpace,
      driftSpace, driftSeries,
      vectors
    ] = await Promise.all([
      runKql(TIMESPACE_QUERIES.signin_time_series(bin), timespan),
      runKql(TIMESPACE_QUERIES.signin_space_hotspots, timespan),
      runKql(TIMESPACE_QUERIES.azure_drift_space_by_region, timespan),
      runKql(TIMESPACE_QUERIES.azure_drift_time_series(bin), timespan),
      runKql(TIMESPACE_QUERIES.drift_vectors, timespan),
    ]);

    res.json({
      mode,
      scanned_at: new Date().toISOString(),
      bin,
      timespan,
      time: {
        risky_signins_series: signinSeries,
        azure_drift_series: driftSeries
      },
      space: {
        signins_hotspots: signinSpace,
        azure_drift_hotspots: driftSpace
      },
      vectors: vectors
    });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});
<div class="card">
  <div class="row">
    <strong>Time-Space Lens (Preview)</strong>
    <span class="right pill">Time series + space hotspots + drift vectors</span>
  </div>

  <div class="row" style="margin-top:10px;">
    <input id="tsSpan" value="P1D" title="timespan (ISO 8601), e.g. PT6H, P1D, P7D" />
    <input id="tsBin" value="15m" title="bin size, e.g. 5m, 15m, 1h" />
    <button id="tsRun">Run Time-Space Scan</button>
  </div>

  <div class="mono" style="margin-top:10px;">Time series (risky sign-ins, drift rate), plus “space” hotspots (regions/countries) and top drift vectors.</div>
  <div class="log" id="tsOut"></div>
</div>

<script>
  // Add inside the existing script IIFE in your UI:
  // (Assumes api(path, body) exists)

  document.getElementById("tsRun").addEventListener("click", async () => {
    try{
      log("Time-Space scan requested (preview).");
      const timespan = document.getElementById("tsSpan").value.trim() || "P1D";
      const bin = document.getElementById("tsBin").value.trim() || "15m";
      const res = await api("/timespace", { mode:"preview", timespan, bin });
      document.getElementById("tsOut").textContent = JSON.stringify(res, null, 2);
      log("Time-Space scan complete.");
    } catch(e){
      log(`Time-Space scan failed: ${e.message}`);
      alert(e.message);
    }
  });
</script>
diff --git a/examples.py b/examples.py
index fdcd0e2986edb6ab27f6e5e0b2fe3912752e187c..c9398f15569af91b5199c7c53130a7e136aaf475 100644
--- a/examples.py
+++ b/examples.py
@@ -231,47 +231,82 @@ def example_7_restriction_modification():
     print("\n--- Adding Environmental Restrictions ---")
     
     restriction1 = RestrictionRule(
         RestrictionType.ENTROPY_COST,
         severity=0.2,
         description="Dimensional instability in area"
     )
     ability.add_restriction(restriction1)
     print(f"After restriction 1: {ability.get_effective_power():.1f}")
     
     restriction2 = RestrictionRule(
         RestrictionType.MATERIAL_ANCHOR,
         severity=0.3,
         description="Requires rare materials to stabilize"
     )
     ability.add_restriction(restriction2)
     print(f"After restriction 2: {ability.get_effective_power():.1f}")
     
     # Remove a restriction
     print("\n--- Removing Restrictions ---")
     if ability.remove_restriction(RestrictionType.ENTROPY_COST):
         print(f"Removed entropy cost restriction")
     print(f"After removal: {ability.get_effective_power():.1f}")
 
 
+def example_8_stabilize_cloud_and_timespace():
+    """Example 8: Stabilizing cloud coherence and time-space continuity."""
+    print("\n" + "="*70)
+    print("EXAMPLE 8: Stabilize the Cloud, Stabilize Time-Space")
+    print("="*70)
+
+    practitioner = MetaphysicalPractitioner(
+        "Continuum Warden",
+        consciousness_level=0.9,
+        max_energy=300.0,
+        energy_pool=300.0
+    )
+
+    cloud_stability = 0.4
+    timespace_stability = 0.35
+
+    print(f"Initial cloud stability: {cloud_stability:.0%}")
+    print(f"Initial time-space stability: {timespace_stability:.0%}")
+
+    result = practitioner.stabilize_cloud_and_timespace(
+        cloud_stability=cloud_stability,
+        timespace_stability=timespace_stability
+    )
+
+    print(f"Success: {result['success']}")
+    print(f"Reason: {result['reason']}")
+    print(f"Energy consumed: {result['energy_consumed']:.1f}")
+
+    if result['success']:
+        print(f"Stabilized cloud level: {result['cloud_stability']:.0%}")
+        print(f"Stabilized time-space level: {result['timespace_stability']:.0%}")
+        print(f"Remaining energy: {result['remaining_energy']:.1f}")
+
+
 def main():
     """Run all examples."""
     print("\n" + "="*70)
     print("METAPHYSICAL CAPABILITIES RESTRICTION SYSTEM")
     print("Game Mechanics & Philosophical Framework Examples")
     print("="*70)
     
     example_1_basic_capability_restriction()
     example_2_balanced_magic_system()
     example_3_philosophical_frameworks()
     example_4_reality_warper()
     example_5_consciousness_degradation()
     example_6_multiple_uses_and_cooldown()
     example_7_restriction_modification()
+    example_8_stabilize_cloud_and_timespace()
     
     print("\n" + "="*70)
     print("Examples completed!")
     print("="*70 + "\n")
 
 
 if __name__ == "__main__":
     main()


def example_8_stabilize_cloud_and_timespace():
    """Example 8: Stabilize cloud state and time-space before execution."""
    print("\n" + "="*70)
    print("EXAMPLE 8: Stabilize Cloud and Time-Space")
    print("="*70)

    operator = create_stabilized_cloud_timespace_operator()
    temporal_anchor = operator.capabilities[0]

    cloud_framework = next(
        framework for framework in operator.philosophical_frameworks
        if isinstance(framework, CloudStabilityFramework)
    )
    spacetime_framework = next(
        framework for framework in operator.philosophical_frameworks
        if isinstance(framework, SpacetimeStabilityFramework)
    )

    cloud_framework.stabilize(0.6)
    spacetime_framework.stabilize(0.7)

    can_use, reason = operator.can_use_capability(temporal_anchor)
    print(f"Before stabilization: {can_use} - {reason}")

    cloud_framework.stabilize(0.95)
    spacetime_framework.stabilize(0.95)
    can_use, reason = operator.can_use_capability(temporal_anchor)
    print(f"After stabilization: {can_use} - {reason}")

    if can_use:
        result = operator.use_capability(temporal_anchor)
        print(f"Temporal Anchor power: {result['power_used']:.1f}")
        print(f"Energy remaining: {result['remaining_energy']:.1f}")
class CloudStabilityFramework(PhilosophicalFramework):
    """Framework that gates metaphysical actions on cloud-system stability."""

    def __init__(self, minimum_stability: float = 0.75):
        self.minimum_stability = max(0.0, min(1.0, minimum_stability))
        self.cloud_stability = 1.0

    def stabilize(self, target_stability: float = 1.0) -> None:
        """Move cloud stability toward a safe level."""
        self.cloud_stability = max(0.0, min(1.0, target_stability))

    def evaluate_restriction(self, capability: MetaphysicalCapability) -> bool:
        return self.cloud_stability >= self.minimum_stability

    def get_restriction_reason(self) -> str:
        return (
            "Cloud stability guard: metaphysical operations are blocked while "
            "distributed state is unstable."
        )


class SpacetimeStabilityFramework(PhilosophicalFramework):
    """Framework for preventing time-space operations during instability."""

    def __init__(self, minimum_stability: float = 0.8):
        self.minimum_stability = max(0.0, min(1.0, minimum_stability))
        self.spacetime_stability = 1.0

    def stabilize(self, target_stability: float = 1.0) -> None:
        """Move spacetime stability toward a safe level."""
        self.spacetime_stability = max(0.0, min(1.0, target_stability))

    def evaluate_restriction(self, capability: MetaphysicalCapability) -> bool:
        if capability.capability_type in {
            CapabilityType.TIME_MANIPULATION,
            CapabilityType.DIMENSIONAL_TRAVEL,
            CapabilityType.REALITY_WARPING,
        }:
            return self.spacetime_stability >= self.minimum_stability
        return True

    def get_restriction_reason(self) -> str:
        return (
            "Time-space stability guard: temporal and dimensional abilities "
            "require stabilized spacetime conditions."
        )

diff --git a/metaphysical_restrictions.py b/metaphysical_restrictions.py
index 2443ccb7c89f840621582951f42986372b6249bc..ffd8e6a0566ccfdc1d0788578626efcb9f579b94 100644
--- a/metaphysical_restrictions.py
+++ b/metaphysical_restrictions.py
@@ -333,25 +333,93 @@ def create_restricted_reality_warper() -> MetaphysicalPractitioner:
     
     reality_warp = MetaphysicalCapability(
         "Reality Warping",
         CapabilityType.REALITY_WARPING,
         base_power_level=85.0
     )
     reality_warp.add_restriction(RestrictionRule(
         RestrictionType.PHILOSOPHICAL_PARADOX,
         severity=0.6,
         description="Cannot create logical contradictions"
     ))
     reality_warp.add_restriction(RestrictionRule(
         RestrictionType.ENTROPY_COST,
         severity=0.5,
         description="Massive entropy increase per use"
     ))
     reality_warp.add_restriction(RestrictionRule(
         RestrictionType.MATERIAL_ANCHOR,
         severity=0.4,
         description="Requires ritual components to ground the effect"
     ))
     
     practitioner.add_capability(reality_warp)
     
     return practitioner
+
+
+def stabilize_everything_everywhere_and_nothing(
+    practitioner: MetaphysicalPractitioner,
+    target_energy_ratio: float = 0.7,
+    target_consciousness: float = 0.8,
+    min_capability_power: float = 15.0,
+    max_capability_power: float = 70.0,
+) -> Dict[str, float]:
+    """
+    Apply a universal stabilization pass across practitioner state.
+
+    This helper intentionally touches "everything, everywhere, and nothing"
+    by balancing global resources (energy, consciousness), local capability
+    power ranges, and empty-state behavior when a practitioner has no
+    capabilities at all.
+
+    Returns a compact metrics dictionary describing the resulting stability.
+    """
+    # Keep input targets in valid ranges.
+    target_energy_ratio = max(0.0, min(1.0, target_energy_ratio))
+    target_consciousness = max(0.0, min(1.0, target_consciousness))
+    min_capability_power = max(0.0, min_capability_power)
+    max_capability_power = max(min_capability_power, max_capability_power)
+
+    # 1) Global stabilization: move core resources toward configurable baselines.
+    practitioner.energy_pool = practitioner.max_energy * target_energy_ratio
+    practitioner.consciousness_level = target_consciousness
+
+    # 2) Local stabilization: clamp extreme capability powers into a stable band.
+    clamped = 0
+    for capability in practitioner.capabilities:
+        if capability.base_power_level < min_capability_power:
+            capability.base_power_level = min_capability_power
+            clamped += 1
+        elif capability.base_power_level > max_capability_power:
+            capability.base_power_level = max_capability_power
+            clamped += 1
+
+        # Ensure every capability has at least one stabilizing restriction.
+        if not capability.restrictions:
+            capability.add_restriction(RestrictionRule(
+                RestrictionType.CONSCIOUSNESS_REQUIREMENT,
+                severity=0.1,
+                description="Universal stabilization baseline"
+            ))
+
+    # 3) "Nothing" stabilization: define a stable score for empty systems.
+    capability_count = len(practitioner.capabilities)
+    if capability_count == 0:
+        effective_average = 0.0
+        void_stability_index = 1.0
+    else:
+        total_effective = sum(
+            capability.get_effective_power() for capability in practitioner.capabilities
+        )
+        effective_average = total_effective / capability_count
+        void_stability_index = max(0.0, 1.0 - (effective_average / 100.0))
+
+    return {
+        "capability_count": float(capability_count),
+        "capabilities_clamped": float(clamped),
+        "energy_ratio": practitioner.energy_pool / practitioner.max_energy
+        if practitioner.max_energy else 0.0,
+        "consciousness": practitioner.consciousness_level,
+        "average_effective_power": effective_average,
+        "void_stability_index": void_stability_index,
+    }
diff --git a/metaphysical_restrictions.py b/metaphysical_restrictions.py
index 2443ccb7c89f840621582951f42986372b6249bc..78a4157f4abc771b0a955e821f91ab9f589cb0ed 100644
--- a/metaphysical_restrictions.py
+++ b/metaphysical_restrictions.py
@@ -333,25 +333,77 @@ def create_restricted_reality_warper() -> MetaphysicalPractitioner:
     
     reality_warp = MetaphysicalCapability(
         "Reality Warping",
         CapabilityType.REALITY_WARPING,
         base_power_level=85.0
     )
     reality_warp.add_restriction(RestrictionRule(
         RestrictionType.PHILOSOPHICAL_PARADOX,
         severity=0.6,
         description="Cannot create logical contradictions"
     ))
     reality_warp.add_restriction(RestrictionRule(
         RestrictionType.ENTROPY_COST,
         severity=0.5,
         description="Massive entropy increase per use"
     ))
     reality_warp.add_restriction(RestrictionRule(
         RestrictionType.MATERIAL_ANCHOR,
         severity=0.4,
         description="Requires ritual components to ground the effect"
     ))
     
     practitioner.add_capability(reality_warp)
     
     return practitioner
+
+
+def stabilize_everything_everywhere_nothing_all_at_once(
+    practitioners: Optional[List[MetaphysicalPractitioner]] = None,
+) -> Dict:
+    """
+    Stabilize every supplied practitioner into a neutral equilibrium state.
+
+    Design goals:
+    - everything: all capabilities are made non-usable with zero base power
+    - everywhere: the operation is applied to every practitioner in the input list
+    - nothing: passing None/empty input is a valid no-op that still returns a
+      deterministic snapshot
+    - all at once: returns a single aggregate report for the whole operation
+    """
+    if not practitioners:
+        return {
+            "stabilized_count": 0,
+            "total_capabilities_disabled": 0,
+            "snapshot": "nothing_to_stabilize",
+        }
+
+    total_capabilities_disabled = 0
+    practitioner_snapshots = []
+
+    for practitioner in practitioners:
+        disabled_here = 0
+
+        for capability in practitioner.capabilities:
+            capability.is_usable = False
+            capability.base_power_level = 0.0
+            disabled_here += 1
+
+        practitioner.energy_pool = 0.0
+        practitioner.consciousness_level = 0.0
+
+        total_capabilities_disabled += disabled_here
+        practitioner_snapshots.append(
+            {
+                "name": practitioner.name,
+                "capabilities_disabled": disabled_here,
+                "energy_pool": practitioner.energy_pool,
+                "consciousness_level": practitioner.consciousness_level,
+            }
+        )
+
+    return {
+        "stabilized_count": len(practitioners),
+        "total_capabilities_disabled": total_capabilities_disabled,
+        "snapshot": "equilibrium_achieved",
+        "practitioners": practitioner_snapshots,
+    }
// OmniScope KQL pack: broad + safe + read-only.
// Each query is designed to be useful if the table exists; if not, it will fail and we mark it unavailable.

const OMNISCOPE = {
  // --- TIME: incidents over time ---
  incidents_time: (bin) => `
SecurityIncident
| where TimeGenerated > ago(7d)
| summarize count() by bin(TimeGenerated, ${bin})
| order by TimeGenerated asc`,

  // --- SPACE: incidents by severity + provider product ---
  incidents_space: `
SecurityIncident
| where TimeGenerated > ago(7d)
| summarize incidents=count() by tostring(Severity), tostring(ProviderName)
| order by incidents desc`,

  // --- IDENTITY TIME: sign-ins over time (Entra) ---
  signins_time: (bin) => `
SigninLogs
| where TimeGenerated > ago(24h)
| summarize count() by bin(TimeGenerated, ${bin})
| order by TimeGenerated asc`,

  // --- IDENTITY SPACE: top countries/regions ---
  signins_space: `
SigninLogs
| where TimeGenerated > ago(24h)
| summarize signins=count() by tostring(LocationDetails.countryOrRegion)
| top 15 by signins desc`,

  // --- AZURE DRIFT TIME: network/policy writes ---
  azure_drift_time: (bin) => `
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue has_any (
  "Microsoft.Network/networkSecurityGroups/securityRules/write",
  "Microsoft.Network/publicIPAddresses/write",
  "Microsoft.Authorization/policyAssignments/write",
  "Microsoft.Authorization/policyDefinitions/write",
  "Microsoft.Authorization/roleAssignments/write"
)
| summarize count() by bin(TimeGenerated, ${bin})
| order by TimeGenerated asc`,

  // --- AZURE DRIFT SPACE: where drift clusters (Location/ResourceProvider) ---
  azure_drift_space: `
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue has_any (
  "Microsoft.Network/networkSecurityGroups/securityRules/write",
  "Microsoft.Network/publicIPAddresses/write",
  "Microsoft.Authorization/policyAssignments/write",
  "Microsoft.Authorization/policyDefinitions/write",
  "Microsoft.Authorization/roleAssignments/write"
)
| summarize ops=count() by tostring(Location), tostring(ResourceProviderValue)
| top 15 by ops desc`,

  // --- DEFENDER: security alerts over time ---
  defender_alerts_time: (bin) => `
SecurityAlert
| where TimeGenerated > ago(24h)
| summarize alerts=count() by bin(TimeGenerated, ${bin})
| order by TimeGenerated asc`,

  // --- DEFENDER SPACE: alerts by product ---
  defender_alerts_space: `
SecurityAlert
| where TimeGenerated > ago(24h)
| summarize alerts=count() by tostring(ProductName)
| top 15 by alerts desc`,

  // --- OPTIONAL: AWS events if present (table name varies; adjust if needed) ---
  aws_time: (bin) => `
AWSCloudTrail
| where TimeGenerated > ago(24h)
| summarize events=count() by bin(TimeGenerated, ${bin})
| order by TimeGenerated asc`,

  aws_space: `
AWSCloudTrail
| where TimeGenerated > ago(24h)
| summarize events=count() by tostring(AwsRegion)
| top 15 by events desc`,

  // --- OPTIONAL: entropy findings if you ingest them ---
  entropy_time: (bin) => `
EntropyFindings_CL
| where TimeGenerated > ago(24h)
| summarize findings=count() by bin(TimeGenerated, ${bin})
| order by TimeGenerated asc`,

  entropy_space: `
EntropyFindings_CL
| where TimeGenerated > ago(24h)
| summarize findings=count() by tostring(source_s), tostring(severity_s)
| top 20 by findings desc`
};

async function tryKql(query, timespan) {
  try {
    const resp = await runKql(query, timespan);
    return { ok: true, resp };
  } catch (e) {
    return { ok: false, error: "Query failed (table missing/connector absent/permissions)", detail: e?.message || String(e) };
  }
}

function clamp01(x){ return Math.max(0, Math.min(1, x)); }

// A transparent “everywhere/nowhere” stability index based on multiple domains.
// Higher counts increase “pressure” in that domain; stability = 100 - pressure*100.
function computeOmniStability(metrics){
  // metrics are counts (numbers). Log-scale them so “all at once” bursts are visible without exploding.
  const L = (n) => Math.min(1, Math.log10(1 + (n||0)) / 3); // 0..1

  const incidentP = L(metrics.incidents || 0);
  const identityP = L(metrics.signins || 0);
  const driftP = L(metrics.azureDrift || 0);
  const alertsP = L(metrics.alerts || 0);
  const awsP = L(metrics.awsEvents || 0);
  const entropyP = L(metrics.entropy || 0);

  // weights (tune to taste)
  const pressure = clamp01(
    0.22*incidentP +
    0.18*identityP +
    0.22*driftP +
    0.18*alertsP +
    0.10*awsP +
    0.10*entropyP
  );

  return {
    stability_index: 100 * (1 - pressure),
    pressure_breakdown: {
      incidents: incidentP, identity: identityP, drift: driftP,
      alerts: alertsP, aws: awsP, entropy: entropyP
    }
  };
}

app.post("/omniscope", async (req, res) => {
  try{
    requireEnv();
    const mode = req.body?.mode || "preview";
    const bin = req.body?.bin || "30m";
    const timespan = req.body?.timespan || "P7D";

    // run broad queries in parallel
    const tasks = {
      incidents_time: tryKql(OMNISCOPE.incidents_time(bin), timespan),
      incidents_space: tryKql(OMNISCOPE.incidents_space, timespan),

      signins_time: tryKql(OMNISCOPE.signins_time(bin), "P1D"),
      signins_space: tryKql(OMNISCOPE.signins_space, "P1D"),

      azure_drift_time: tryKql(OMNISCOPE.azure_drift_time(bin), "P1D"),
      azure_drift_space: tryKql(OMNISCOPE.azure_drift_space, "P1D"),

      defender_alerts_time: tryKql(OMNISCOPE.defender_alerts_time(bin), "P1D"),
      defender_alerts_space: tryKql(OMNISCOPE.defender_alerts_space, "P1D"),

      aws_time: tryKql(OMNISCOPE.aws_time(bin), "P1D"),
      aws_space: tryKql(OMNISCOPE.aws_space, "P1D"),

      entropy_time: tryKql(OMNISCOPE.entropy_time(bin), "P1D"),
      entropy_space: tryKql(OMNISCOPE.entropy_space, "P1D"),
    };

    const results = {};
    for (const [k, p] of Object.entries(tasks)) results[k] = await p;

    // extract simple counts for stability (if ok)
    const countFrom = (r) => {
      if(!r?.ok) return 0;
      const t = r.resp?.tables?.[0];
      if(!t) return 0;
      // prefer first row first column for summarize count() queries
      if(t.rows?.length === 1 && t.rows[0]?.length >= 1 && typeof t.rows[0][0] === "number") return t.rows[0][0];
      return t.rows?.length || 0;
    };

    const metrics = {
      incidents: countFrom(results.incidents_space),
      signins: countFrom(results.signins_space),
      azureDrift: countFrom(results.azure_drift_space),
      alerts: countFrom(results.defender_alerts_space),
      awsEvents: countFrom(results.aws_space),
      entropy: countFrom(results.entropy_space),
    };

    const stability = computeOmniStability(metrics);

    res.json({
      mode,
      scanned_at: new Date().toISOString(),
      bin,
      timespan,
      stability,
      metrics,
      results
    });
  } catch(e){
    res.status(400).json({ error: e.message });
  }
});
<div class="card">
  <div class="row">
    <strong>OmniScope — Everywhere / Nowhere (Preview)</strong>
    <span class="right pill">Unified time-space snapshot</span>
  </div>

  <div class="row" style="margin-top:10px;">
    <input id="omniSpan" value="P7D" title="timespan (ISO), e.g. P1D, P7D" />
    <input id="omniBin" value="30m" title="bin, e.g. 5m, 30m, 1h" />
    <button id="omniRun">Run OmniScope</button>
  </div>

  <div class="mono" style="margin-top:10px;">
    This queries Sentinel/Log Analytics across multiple “domains” (incidents, identity, drift, alerts, optional AWS, optional entropy findings).
    Missing connectors appear as unavailable.
  </div>

  <div class="log" id="omniOut"></div>
</div>

<script>
  document.getElementById("omniRun").addEventListener("click", async () => {
    try{
      log("OmniScope requested (preview).");
      const timespan = document.getElementById("omniSpan").value.trim() || "P7D";
      const bin = document.getElementById("omniBin").value.trim() || "30m";
      const res = await api("/omniscope", { mode:"preview", timespan, bin });
      document.getElementById("omniOut").textContent = JSON.stringify(res, null, 2);
      log(`OmniScope complete: stability=${res.stability.stability_index.toFixed(1)}%`);
    } catch(e){
      log(`OmniScope failed: ${e.message}`);
      alert(e.message);
    }
  });
</script>
diff --git a/domain_user_cleanup.py b/domain_user_cleanup.py
new file mode 100644
index 0000000000000000000000000000000000000000..a028c89ba139887c368bdd05bae1a6622be3d054
--- /dev/null
+++ b/domain_user_cleanup.py
@@ -0,0 +1,49 @@
+"""Utilities for removing users from hidden, entropic domains."""
+
+from __future__ import annotations
+
+from copy import deepcopy
+from typing import Any, Iterable
+
+
+def _normalize(value: Any) -> str:
+    """Normalize arbitrary values for case-insensitive comparisons."""
+    return str(value).strip().lower()
+
+
+def _is_hidden_entropic_domain(domain: Any) -> bool:
+    """Return True when a domain should have its users removed."""
+    normalized = _normalize(domain)
+    tokens = {token for token in normalized.replace("_", " ").replace("-", " ").split() if token}
+
+    return (
+        "hidden" in tokens and "entropic" in tokens
+    ) or normalized in {"hidden entropic", "entropic hidden"}
+
+
+def remove_users_from_hidden_entropic_domains(domains: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
+    """Return a deep-copied domain list with users removed from hidden+entropic domains.
+
+    Each input domain is expected to be a dictionary and may have keys such as
+    ``name``, ``type``, and ``users``. When the domain name/type indicates the
+    domain is both hidden and entropic, its ``users`` value is replaced with an
+    empty list.
+    """
+    sanitized_domains = deepcopy(list(domains))
+
+    for domain in sanitized_domains:
+        domain_marker = domain.get("name") or domain.get("type") or ""
+        if _is_hidden_entropic_domain(domain_marker):
+            domain["users"] = []
+
+    return sanitized_domains
+
+
+if __name__ == "__main__":
+    sample_domains = [
+        {"name": "hidden-entropic", "users": ["alice", "bob"]},
+        {"name": "public-stable", "users": ["carol"]},
+        {"type": "entropic hidden", "users": ["dave"]},
+    ]
+
+    print(remove_users_from_hidden_entropic_domains(sample_domains))
diff --git a/hidden_entropic_domain_cleanup.py b/hidden_entropic_domain_cleanup.py
new file mode 100644
index 0000000000000000000000000000000000000000..035cb5d432c272845927cdfbe1bb82a1a7ab2c2d
--- /dev/null
+++ b/hidden_entropic_domain_cleanup.py
@@ -0,0 +1,80 @@
+"""Utilities for removing users from hidden entropic domains."""
+
+from __future__ import annotations
+
+from copy import deepcopy
+from typing import Any, Dict, Iterable, List, Tuple
+
+
+def _normalize(value: Any) -> str:
+    """Normalize arbitrary values for case-insensitive string comparison."""
+    return str(value).strip().lower()
+
+
+def remove_users_from_hidden_entropic_domains(
+    domains: Iterable[Dict[str, Any]],
+) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
+    """Remove all users from domains marked as both hidden and entropic.
+
+    Args:
+        domains: Iterable of domain records. Each record should contain a
+            ``users`` list and can contain these flags/fields:
+              - ``visibility``: expected values like ``hidden``/``public``
+              - ``state``: expected values like ``entropic``/``stable``
+              - ``hidden``: boolean fallback for visibility
+              - ``entropic``: boolean fallback for state
+
+    Returns:
+        A tuple ``(updated_domains, removal_log)`` where:
+          - updated_domains contains deep-copied domain dictionaries with the
+            ``users`` list cleared for matching domains.
+          - removal_log contains one entry per modified domain.
+    """
+    updated_domains = deepcopy(list(domains))
+    removal_log: List[Dict[str, Any]] = []
+
+    for domain in updated_domains:
+        visibility_hidden = _normalize(domain.get("visibility", "")) == "hidden" or bool(
+            domain.get("hidden")
+        )
+        state_entropic = _normalize(domain.get("state", "")) == "entropic" or bool(
+            domain.get("entropic")
+        )
+
+        if visibility_hidden and state_entropic:
+            users = list(domain.get("users", []))
+            if users:
+                domain["users"] = []
+                removal_log.append(
+                    {
+                        "domain_id": domain.get("id"),
+                        "domain_name": domain.get("name"),
+                        "removed_user_count": len(users),
+                        "removed_users": users,
+                    }
+                )
+
+    return updated_domains, removal_log
+
+
+if __name__ == "__main__":
+    sample_domains = [
+        {
+            "id": "D-001",
+            "name": "Whisper Vault",
+            "visibility": "hidden",
+            "state": "entropic",
+            "users": ["alice", "bob", "charlie"],
+        },
+        {
+            "id": "D-002",
+            "name": "Open Plains",
+            "visibility": "public",
+            "state": "stable",
+            "users": ["diana"],
+        },
+    ]
+
+    cleaned, audit = remove_users_from_hidden_entropic_domains(sample_domains)
+    print("Updated domains:\n", cleaned)
+    print("\nRemoval log:\n", audit)
diff --git a/domain_user_cleanup.py b/domain_user_cleanup.py
new file mode 100644
index 0000000000000000000000000000000000000000..f3b22e5ced1e2a185e6e0ad6797759accc1e0e35
--- /dev/null
+++ b/domain_user_cleanup.py
@@ -0,0 +1,78 @@
+"""Utilities to remove users assigned to hidden, entropic domains."""
+
+from __future__ import annotations
+
+from dataclasses import dataclass, asdict
+from typing import Iterable, List, Sequence, Tuple
+
+
+@dataclass(frozen=True)
+class UserRecord:
+    """Simple user model with a domain assignment."""
+
+    user_id: str
+    username: str
+    domain: str
+
+
+def remove_users_from_hidden_entropic_domains(
+    users: Sequence[UserRecord],
+    blocked_domains: Iterable[str] = ("hidden", "entropic"),
+) -> Tuple[List[UserRecord], List[UserRecord]]:
+    """Remove users whose domain matches blocked values.
+
+    Returns a tuple containing:
+      1) the remaining users
+      2) users removed from blocked domains
+    """
+
+    blocked = {domain.strip().lower() for domain in blocked_domains}
+
+    remaining: List[UserRecord] = []
+    removed: List[UserRecord] = []
+
+    for user in users:
+        if user.domain.strip().lower() in blocked:
+            removed.append(user)
+        else:
+            remaining.append(user)
+
+    return remaining, removed
+
+
+def remove_from_dict_rows(
+    rows: Sequence[dict],
+    blocked_domains: Iterable[str] = ("hidden", "entropic"),
+) -> Tuple[List[dict], List[dict]]:
+    """Dict-based wrapper for integrations that do not use dataclasses."""
+
+    users = [
+        UserRecord(
+            user_id=str(row.get("user_id", "")),
+            username=str(row.get("username", "")),
+            domain=str(row.get("domain", "")),
+        )
+        for row in rows
+    ]
+
+    remaining, removed = remove_users_from_hidden_entropic_domains(users, blocked_domains)
+    return [asdict(user) for user in remaining], [asdict(user) for user in removed]
+
+
+if __name__ == "__main__":
+    sample_users = [
+        UserRecord("u1", "alice", "public"),
+        UserRecord("u2", "bob", "hidden"),
+        UserRecord("u3", "cora", "entropic"),
+        UserRecord("u4", "dave", "trusted"),
+    ]
+
+    kept, removed = remove_users_from_hidden_entropic_domains(sample_users)
+
+    print("Kept users:")
+    for user in kept:
+        print(f" - {user.username} ({user.domain})")
+
+    print("\nRemoved users:")
+    for user in removed:
+        print(f" - {user.username} ({user.domain})")
diff --git a/domain_cleanup.py b/domain_cleanup.py
new file mode 100644
index 0000000000000000000000000000000000000000..5909553909b2f1c51e24edff81e3176c4c18aa87
--- /dev/null
+++ b/domain_cleanup.py
@@ -0,0 +1,58 @@
+"""Utilities for removing users from hidden, entropic domains."""
+
+from copy import deepcopy
+from typing import Any, Dict, Iterable, List, Tuple
+
+
+def _is_hidden_entropic(domain: Dict[str, Any]) -> bool:
+    """Return True when a domain is both hidden and entropic."""
+    tags = {str(tag).strip().lower() for tag in domain.get("tags", [])}
+
+    is_hidden = bool(domain.get("hidden", False)) or "hidden" in tags
+    is_entropic = bool(domain.get("entropic", False)) or "entropic" in tags
+
+    return is_hidden and is_entropic
+
+
+def remove_users_from_hidden_entropic_domains(
+    domains: Iterable[Dict[str, Any]],
+) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
+    """
+    Remove all users from domains marked as both hidden and entropic.
+
+    Parameters
+    ----------
+    domains:
+        Iterable of domain dictionaries. Each domain may contain keys like:
+        - `name`: domain name
+        - `users`: list of user ids or usernames
+        - `hidden`: bool
+        - `entropic`: bool
+        - `tags`: iterable of text tags
+
+    Returns
+    -------
+    tuple[list[dict], list[dict]]
+        A tuple with:
+        1) A deep-copied list of updated domains
+        2) An audit log list describing which users were removed per domain
+    """
+    updated_domains = deepcopy(list(domains))
+    audit_log: List[Dict[str, Any]] = []
+
+    for domain in updated_domains:
+        if not _is_hidden_entropic(domain):
+            continue
+
+        previous_users = list(domain.get("users", []))
+        domain["users"] = []
+
+        audit_log.append(
+            {
+                "domain": domain.get("name", "<unnamed>"),
+                "removed_user_count": len(previous_users),
+                "removed_users": previous_users,
+            }
+        )
+
+    return updated_domains, audit_log
diff --git a/test_domain_cleanup.py b/test_domain_cleanup.py
new file mode 100644
index 0000000000000000000000000000000000000000..3a05a6e014cb9a0d8e5436943d34d8300f47b659
--- /dev/null
+++ b/test_domain_cleanup.py
@@ -0,0 +1,55 @@
+import unittest
+
+from domain_cleanup import remove_users_from_hidden_entropic_domains
+
+
+class DomainCleanupTests(unittest.TestCase):
+    def test_removes_users_only_from_hidden_and_entropic_domains(self):
+        domains = [
+            {
+                "name": "obscura",
+                "hidden": True,
+                "entropic": True,
+                "users": ["u1", "u2"],
+            },
+            {
+                "name": "hidden_only",
+                "hidden": True,
+                "entropic": False,
+                "users": ["u3"],
+            },
+            {
+                "name": "tagged_domain",
+                "tags": ["hidden", "entropic"],
+                "users": ["u4"],
+            },
+        ]
+
+        cleaned, audit = remove_users_from_hidden_entropic_domains(domains)
+
+        self.assertEqual(cleaned[0]["users"], [])
+        self.assertEqual(cleaned[1]["users"], ["u3"])
+        self.assertEqual(cleaned[2]["users"], [])
+
+        self.assertEqual(audit[0]["domain"], "obscura")
+        self.assertEqual(audit[0]["removed_user_count"], 2)
+        self.assertEqual(audit[1]["domain"], "tagged_domain")
+
+    def test_does_not_mutate_input(self):
+        original = [
+            {
+                "name": "obscura",
+                "hidden": True,
+                "entropic": True,
+                "users": ["u1"],
+            }
+        ]
+
+        cleaned, _ = remove_users_from_hidden_entropic_domains(original)
+
+        self.assertEqual(original[0]["users"], ["u1"])
+        self.assertEqual(cleaned[0]["users"], [])
+
+
+if __name__ == "__main__":
+    unittest.main()
                 ┌────────────────────┐
                 │  Sentinel (Core)   │
                 │  Log Analytics     │
                 └─────────┬──────────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
   Azure Control      AWS Organization     GCP (Optional)
   - AzureActivity    - CloudTrail         - Admin logs
   - SigninLogs       - Config             - Audit logs
   - Defender         - GuardDuty
        │                  │
        └───────────── OmniScope Engine ──────────────┘
                           │
                   Stabilization Planner
                           │
                   Guarded Remediation
  {
  "properties": {
    "displayName": "Global Exposure Guardrails",
    "policyType": "Custom",
    "mode": "All",
    "description": "Deny public network exposure and require encryption.",
    "parameters": {},
    "policyRule": {
      "if": {
        "anyOf": [
          {
            "field": "Microsoft.Storage/storageAccounts/allowBlobPublicAccess",
            "equals": true
          },
          {
            "field": "Microsoft.Network/networkSecurityGroups/securityRules[*].sourceAddressPrefix",
            "equals": "0.0.0.0/0"
          }
        ]
      },
      "then": {
        "effect": "deny"
      }
    }
  }
}
  Global Stability = 100
  - Weighted Drift
  - Weighted Identity Risk
  - Weighted Exposure Changes
  Global Stability = 100
  - Weighted Drift
  - Weighted Identity Risk
  - Weighted Exposure Changes
  - Weighted Alert Volume
  {
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyPublicS3",
      "Effect": "Deny",
      "Action": "s3:PutBucketPolicy",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "s3:policyAllowsPublicAccess": "true"
        }
      }
    },
    {
      "Sid": "DenyWideOpenSecurityGroups",
      "Effect": "Deny",
      "Action": "ec2:AuthorizeSecurityGroupIngress",
      "Resource": "*",
      "Condition": {
        "IpAddress": {
          "ec2:SourceIp": "0.0.0.0/0"
        }
      }
    }
  ]
}
  Stability = 100
 - Drift Pressure
 - Identity Risk Pressure
 - Exposure Pressure
 - Alert Burst Pressure
  [5 min Sentinel Analytics]
        ↓
[Time-Space Heatmap]
        ↓
[Hotspot Detection]
        ↓
[Guarded Plan]
        ↓
[Containment Automation]
        ↓
[Recalculate Stability]
  - Weighted Alert Volume
[5 min Sentinel Analytics]
        ↓
[Time-Space Heatmap]
        ↓
[Hotspot Detection]
        ↓
[Guarded Plan]
        ↓
[Containment Automation]
        ↓
[Recalculate Stability]
  omnicontrol/
├── azure/
│   ├── bicep/
│   │   ├── mg-root-baseline.bicep
│   │   ├── policy-initiative-exposure.bicep
│   │   ├── sentinel-workspace.bicep
│   │   └── defender-enablement.bicep
│   └── policy/
│       ├── exposure-deny.json
│       ├── encryption-required.json
│       └── logging-required.json
│
├── aws/
│   ├── terraform/
│   │   ├── org-root-baseline.tf
│   │   ├── guardduty-org.tf
│   │   ├── securityhub-org.tf
│   │   └── config-recorder.tf
│   └── scp/
│       ├── deny-public-s3.json
│       ├── deny-wide-open-sg.json
│       └── enforce-mfa.json
│
├── sentinel/
│   ├── analytics/
│   │   ├── drift-detection.kql
│   │   ├── identity-risk.kql
│   │   └── exposure-burst.kql
│   ├── playbooks/
│   │   ├── isolate-vm.json
│   │   ├── disable-user.json
│   │   └── revoke-tokens.json
│
├── graph-engine/
│   ├── ingest.py
│   ├── stability_model.py
│   └── topology_builder.py
│
└── orchestration/
    ├── rollout-plan.yaml
    └── stabilize.py
  targetScope = 'managementGroup'

param mgId string

resource exposureInitiative 'Microsoft.Authorization/policySetDefinitions@2021-06-01' = {
  name: 'GlobalExposureGuardrails'
  properties: {
    displayName: 'Global Exposure Guardrails'
    policyType: 'Custom'
    policies: [
      {
        policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/exposure-deny'
      }
    ]
  }
}

resource assign 'Microsoft.Authorization/policyAssignments@2021-06-01' = {
  name: 'GlobalExposureAssignment'
  properties: {
    displayName: 'Assign Global Exposure Guardrails'
    policyDefinitionId: exposureInitiative.id
    enforcementMode: 'DoNotEnforce' // Preview mode
  }
}
  
terraform plan
AzureActivity
| where TimeGenerated > ago(1h)
| where OperationNameValue has_any (
  "Microsoft.Network/networkSecurityGroups/securityRules/write",
  "Microsoft.Authorization/roleAssignments/write"
)
| summarize DriftCount=count() by ResourceGroup, Location
| order by DriftCount desc
SigninLogs
| where TimeGenerated > ago(1h)
| summarize Risky=countif(RiskLevelDuringSignIn != "none") by LocationDetails.countryOrRegion
| order by Risky desc
{
  "definition": {
    "actions": {
      "Disable_User": {
        "type": "Http",
        "inputs": {
          "method": "POST",
          "uri": "https://graph.microsoft.com/v1.0/users/{userId}/accountEnabled",
          "body": {
            "accountEnabled": false
          }
        }
      }
    }
  },
  "parameters": {
    "previewMode": {
      "type": "bool",
      "defaultValue": true
    }
  }
}
import math

def pressure(n):
    return min(1.0, math.log10(1 + n) / 3)

def compute_stability(metrics):
    weighted = (
        0.25 * pressure(metrics.get("drift", 0)) +
        0.25 * pressure(metrics.get("identity", 0)) +
        0.25 * pressure(metrics.get("exposure", 0)) +
        0.25 * pressure(metrics.get("alerts", 0))
    )
    return 100 * (1 - weighted)

if __name__ == "__main__":
    sample = {
        "drift": 120,
        "identity": 34,
        "exposure": 10,
        "alerts": 55
    }
    print("Stability Index:", compute_stability(sample))
import networkx as nx

def build_topology(resources, identities, relationships):
    g = nx.Graph()

    for r in resources:
        g.add_node(r["id"], type="resource")

    for i in identities:
        g.add_node(i["id"], type="identity")

    for rel in relationships:
        g.add_edge(rel["source"], rel["target"], relation=rel["type"])

    return g

def detect_high_risk_clusters(graph):
    clusters = nx.connected_components(graph)
    return [c for c in clusters if len(c) > 10]
phase_1:
  - enable_sentinel_connectors
  - deploy_policy_initiatives_preview
  - terraform_plan_org_baseline

phase_2:
  - review_drift_heatmap
  - enable_guarded_playbooks
  - enforce_conditional_access_staged

phase_3:
  - switch_policy_enforcement_mode
  - attach_scp_org_root
  - enable_auto_containment_high_only

continuous:
  - 5_minute_scan
  - weekly_stability_report
  - monthly_policy_review
import yaml

def run_phase(phase):
    print(f"=== Running {phase} (preview mode) ===")

if __name__ == "__main__":
    plan = yaml.safe_load(open("rollout-plan.yaml"))
    for phase in plan:
        run_phase(phase)
diff --git a/internet_cloud_hygiene_audit.py b/internet_cloud_hygiene_audit.py
new file mode 100644
index 0000000000000000000000000000000000000000..18379b1f39df1fd30df28d1209d5def82d2f707e
--- /dev/null
+++ b/internet_cloud_hygiene_audit.py
@@ -0,0 +1,288 @@
+#!/usr/bin/env python3
+"""
+Defensive internet/cloud hygiene auditor.
+
+This script is intentionally limited to assets you own/manage.
+It performs non-invasive checks and produces a JSON report with
+findings and suggested remediation actions.
+"""
+
+from __future__ import annotations
+
+import argparse
+import json
+import socket
+import ssl
+import sys
+from dataclasses import asdict, dataclass
+from datetime import datetime, timezone
+from http.client import HTTPConnection, HTTPSConnection
+from pathlib import Path
+from typing import Dict, List, Optional
+from urllib.parse import urlparse
+
+
+@dataclass
+class Finding:
+    target: str
+    category: str
+    severity: str
+    message: str
+    remediation: str
+
+
+def _now_utc() -> datetime:
+    return datetime.now(timezone.utc)
+
+
+def _parse_host_port(target: str) -> tuple[str, int, bool]:
+    parsed = urlparse(target if "://" in target else f"https://{target}")
+    host = parsed.hostname or target
+    https = parsed.scheme == "https" or parsed.scheme == ""
+    port = parsed.port or (443 if https else 80)
+    return host, port, https
+
+
+def check_tls_certificate(target: str, min_valid_days: int = 15) -> List[Finding]:
+    findings: List[Finding] = []
+    host, port, _ = _parse_host_port(target)
+
+    ctx = ssl.create_default_context()
+    with socket.create_connection((host, port), timeout=5) as sock:
+        with ctx.wrap_socket(sock, server_hostname=host) as secure_sock:
+            cert = secure_sock.getpeercert()
+
+    not_after_raw = cert.get("notAfter")
+    if not not_after_raw:
+        findings.append(
+            Finding(
+                target=target,
+                category="tls",
+                severity="high",
+                message="TLS certificate does not include expiry metadata.",
+                remediation="Replace certificate with one from a trusted CA.",
+            )
+        )
+        return findings
+
+    expiry = datetime.strptime(not_after_raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
+    days_left = (expiry - _now_utc()).days
+    if days_left < 0:
+        findings.append(
+            Finding(
+                target=target,
+                category="tls",
+                severity="critical",
+                message=f"TLS certificate expired {abs(days_left)} days ago.",
+                remediation="Renew certificate immediately and deploy via automated rotation.",
+            )
+        )
+    elif days_left < min_valid_days:
+        findings.append(
+            Finding(
+                target=target,
+                category="tls",
+                severity="medium",
+                message=f"TLS certificate expires in {days_left} days.",
+                remediation="Renew certificate and enable expiry monitoring alerts.",
+            )
+        )
+    return findings
+
+
+def check_security_headers(target: str) -> List[Finding]:
+    findings: List[Finding] = []
+    host, port, https = _parse_host_port(target)
+    conn = HTTPSConnection(host, port, timeout=5) if https else HTTPConnection(host, port, timeout=5)
+    conn.request("GET", "/")
+    response = conn.getresponse()
+    headers = {k.lower(): v for k, v in response.getheaders()}
+    conn.close()
+
+    required = {
+        "strict-transport-security": "Add HSTS with an appropriate max-age.",
+        "content-security-policy": "Define a restrictive CSP to reduce XSS risk.",
+        "x-content-type-options": "Set X-Content-Type-Options: nosniff.",
+        "x-frame-options": "Set X-Frame-Options: DENY or SAMEORIGIN.",
+    }
+
+    for header, remediation in required.items():
+        if header not in headers:
+            findings.append(
+                Finding(
+                    target=target,
+                    category="headers",
+                    severity="medium",
+                    message=f"Missing security header: {header}",
+                    remediation=remediation,
+                )
+            )
+    return findings
+
+
+def check_open_ports(host: str, ports: List[int]) -> List[Finding]:
+    findings: List[Finding] = []
+    for port in ports:
+        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
+            sock.settimeout(1)
+            result = sock.connect_ex((host, port))
+            if result == 0:
+                findings.append(
+                    Finding(
+                        target=host,
+                        category="network",
+                        severity="info",
+                        message=f"Port {port} is reachable.",
+                        remediation="Confirm this port is required and restricted by firewall rules.",
+                    )
+                )
+    return findings
+
+
+def check_s3_public_access(bucket_names: List[str]) -> List[Finding]:
+    findings: List[Finding] = []
+    if not bucket_names:
+        return findings
+
+    try:
+        import boto3
+        from botocore.exceptions import ClientError
+    except Exception:
+        return [
+            Finding(
+                target="aws:s3",
+                category="cloud",
+                severity="warning",
+                message="boto3 unavailable; skipped S3 checks.",
+                remediation="Install boto3 and configure AWS credentials to run cloud checks.",
+            )
+        ]
+
+    s3 = boto3.client("s3")
+    for bucket in bucket_names:
+        try:
+            pab = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
+            if not all(pab.values()):
+                findings.append(
+                    Finding(
+                        target=f"s3://{bucket}",
+                        category="cloud",
+                        severity="high",
+                        message="Public access block is not fully enabled.",
+                        remediation="Enable all S3 public access block settings.",
+                    )
+                )
+        except ClientError as exc:
+            findings.append(
+                Finding(
+                    target=f"s3://{bucket}",
+                    category="cloud",
+                    severity="warning",
+                    message=f"Unable to evaluate bucket: {exc.response.get('Error', {}).get('Code', 'Unknown')}",
+                    remediation="Verify bucket exists and your IAM role has read access.",
+                )
+            )
+    return findings
+
+
+def audit_targets(
+    web_targets: List[str],
+    port_targets: Dict[str, List[int]],
+    s3_buckets: Optional[List[str]] = None,
+) -> List[Finding]:
+    findings: List[Finding] = []
+    for target in web_targets:
+        try:
+            findings.extend(check_tls_certificate(target))
+            findings.extend(check_security_headers(target))
+        except Exception as exc:
+            findings.append(
+                Finding(
+                    target=target,
+                    category="availability",
+                    severity="warning",
+                    message=f"Target unreachable for HTTP/TLS checks: {exc}",
+                    remediation="Validate DNS, firewall, and service health before re-running.",
+                )
+            )
+
+    for host, ports in port_targets.items():
+        try:
+            findings.extend(check_open_ports(host, ports))
+        except Exception as exc:
+            findings.append(
+                Finding(
+                    target=host,
+                    category="network",
+                    severity="warning",
+                    message=f"Port scan failed: {exc}",
+                    remediation="Confirm host is reachable and port list is valid.",
+                )
+            )
+
+    findings.extend(check_s3_public_access(s3_buckets or []))
+    return findings
+
+
+def parse_args(argv: List[str]) -> argparse.Namespace:
+    parser = argparse.ArgumentParser(
+        description="Defensive auditor for internet-facing services and cloud resources you own."
+    )
+    parser.add_argument("--web", nargs="*", default=[], help="Web targets, e.g. https://example.com")
+    parser.add_argument(
+        "--ports",
+        nargs="*",
+        default=[],
+        help="Host and ports in form host:22,80,443 (repeatable)",
+    )
+    parser.add_argument("--s3-buckets", nargs="*", default=[], help="S3 bucket names to audit")
+    parser.add_argument("--out", default="hygiene_report.json", help="Output JSON report path")
+    return parser.parse_args(argv)
+
+
+def parse_port_targets(raw_items: List[str]) -> Dict[str, List[int]]:
+    parsed: Dict[str, List[int]] = {}
+    for item in raw_items:
+        host, _, ports_csv = item.partition(":")
+        if not host or not ports_csv:
+            continue
+        ports = []
+        for raw_port in ports_csv.split(","):
+            raw_port = raw_port.strip()
+            if raw_port.isdigit():
+                ports.append(int(raw_port))
+        if ports:
+            parsed[host] = ports
+    return parsed
+
+
+def main(argv: List[str]) -> int:
+    args = parse_args(argv)
+    findings = audit_targets(
+        web_targets=args.web,
+        port_targets=parse_port_targets(args.ports),
+        s3_buckets=args.s3_buckets,
+    )
+
+    report = {
+        "generated_at_utc": _now_utc().isoformat(),
+        "summary": {
+            "total_findings": len(findings),
+            "critical": sum(1 for f in findings if f.severity == "critical"),
+            "high": sum(1 for f in findings if f.severity == "high"),
+            "medium": sum(1 for f in findings if f.severity == "medium"),
+            "warning": sum(1 for f in findings if f.severity == "warning"),
+            "info": sum(1 for f in findings if f.severity == "info"),
+        },
+        "findings": [asdict(f) for f in findings],
+    }
+
+    out_path = Path(args.out)
+    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
+    print(f"Report written to: {out_path}")
+    print(json.dumps(report["summary"], indent=2))
+    return 0
+
+
+if __name__ == "__main__":
+    raise SystemExit(main(sys.argv[1:]))
diff --git a/internet_hygiene_audit.py b/internet_hygiene_audit.py
new file mode 100644
index 0000000000000000000000000000000000000000..da1ee5812f94c888fa1fbb1727badc3bdc9d6eb2
--- /dev/null
+++ b/internet_hygiene_audit.py
@@ -0,0 +1,236 @@
+#!/usr/bin/env python3
+"""Internet + cloud hygiene scanner for assets you own.
+
+This script is intentionally defensive:
+- It only crawls URLs inside allowed domains.
+- It checks basic web hygiene signals (HTTPS, security headers, forms).
+- It scans local cloud/IaC files for high-risk misconfig/secret patterns.
+
+Use this only against infrastructure you are authorized to test.
+"""
+
+from __future__ import annotations
+
+import argparse
+import json
+import re
+from collections import deque
+from dataclasses import asdict, dataclass, field
+from pathlib import Path
+from typing import Iterable
+from urllib.parse import urljoin, urlparse
+
+import ssl
+from urllib.request import Request, urlopen
+
+SECRET_PATTERNS = {
+    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
+    "aws_secret_key": re.compile(r"(?i)aws(.{0,20})?(secret|private)?(.{0,20})?(key|token)\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{40}[\"']?"),
+    "github_pat": re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
+    "private_key": re.compile(r"-----BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY-----"),
+}
+
+RISKY_IAC_PATTERNS = {
+    "public_s3_acl": re.compile(r'(?i)acl\s*=\s*"public-read"'),
+    "public_ingress_anywhere": re.compile(r"0\.0\.0\.0/0"),
+    "wildcard_admin_policy": re.compile(r'"Action"\s*:\s*"\*"'),
+}
+
+FILE_GLOBS = [
+    "*.tf",
+    "*.tfvars",
+    "*.yaml",
+    "*.yml",
+    "*.json",
+    "*.env",
+    "Dockerfile",
+    "*.py",
+    "*.js",
+]
+
+
+@dataclass
+class WebIssue:
+    url: str
+    severity: str
+    category: str
+    detail: str
+
+
+@dataclass
+class FileIssue:
+    file: str
+    line: int
+    severity: str
+    category: str
+    snippet: str
+
+
+@dataclass
+class AuditReport:
+    start_urls: list[str]
+    allowed_domains: list[str]
+    pages_scanned: int = 0
+    web_issues: list[WebIssue] = field(default_factory=list)
+    file_issues: list[FileIssue] = field(default_factory=list)
+
+    def to_json(self) -> str:
+        payload = {
+            "start_urls": self.start_urls,
+            "allowed_domains": self.allowed_domains,
+            "pages_scanned": self.pages_scanned,
+            "web_issues": [asdict(i) for i in self.web_issues],
+            "file_issues": [asdict(i) for i in self.file_issues],
+        }
+        return json.dumps(payload, indent=2)
+
+
+def normalize_domain(host: str) -> str:
+    return host.lower().lstrip(".")
+
+
+def is_allowed(url: str, allowed_domains: set[str]) -> bool:
+    host = normalize_domain(urlparse(url).hostname or "")
+    return any(host == domain or host.endswith(f".{domain}") for domain in allowed_domains)
+
+
+def extract_links(base_url: str, html: str) -> Iterable[str]:
+    for href in re.findall(r"href=[\"']([^\"']+)[\"']", html, flags=re.IGNORECASE):
+        link = urljoin(base_url, href)
+        if link.startswith("http"):
+            yield link
+
+
+def scan_web(start_urls: list[str], allowed_domains: set[str], max_pages: int, timeout: float) -> tuple[int, list[WebIssue]]:
+    visited: set[str] = set()
+    queue = deque(start_urls)
+    issues: list[WebIssue] = []
+
+    ssl_ctx = ssl.create_default_context()
+
+    while queue and len(visited) < max_pages:
+        url = queue.popleft()
+        if url in visited or not is_allowed(url, allowed_domains):
+            continue
+        visited.add(url)
+
+        try:
+            req = Request(url, headers={"User-Agent": "HygieneAuditBot/1.0"})
+            with urlopen(req, timeout=timeout, context=ssl_ctx) as response:
+                final_url = response.geturl()
+                headers = {k: v for k, v in response.headers.items()}
+                body = response.read(1_000_000).decode("utf-8", errors="ignore")
+        except Exception as err:
+            issues.append(WebIssue(url, "medium", "availability", f"Request failed: {err}"))
+            continue
+
+        if final_url.startswith("http://"):
+            issues.append(WebIssue(final_url, "high", "transport", "Endpoint serves plaintext HTTP."))
+
+        if "Strict-Transport-Security" not in headers:
+            issues.append(WebIssue(final_url, "medium", "headers", "Missing HSTS header."))
+        if "Content-Security-Policy" not in headers:
+            issues.append(WebIssue(final_url, "medium", "headers", "Missing CSP header."))
+        if "X-Frame-Options" not in headers:
+            issues.append(WebIssue(final_url, "low", "headers", "Missing X-Frame-Options header."))
+
+        if re.search(r"<form[^>]+method=[\"']?post", body, flags=re.IGNORECASE) and "csrf" not in body.lower():
+            issues.append(WebIssue(final_url, "medium", "app", "POST form found; no obvious CSRF token marker."))
+
+        for link in extract_links(final_url, body):
+            if link not in visited and is_allowed(link, allowed_domains):
+                queue.append(link)
+
+    return len(visited), issues
+
+
+def scan_files(root: Path) -> list[FileIssue]:
+    issues: list[FileIssue] = []
+
+    candidates: set[Path] = set()
+    for glob_pattern in FILE_GLOBS:
+        candidates.update(root.rglob(glob_pattern))
+
+    for path in sorted(candidates):
+        if path.is_dir() or path.stat().st_size > 1_500_000:
+            continue
+
+        try:
+            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
+        except OSError:
+            continue
+
+        for i, line in enumerate(lines, start=1):
+            for category, pattern in SECRET_PATTERNS.items():
+                if pattern.search(line):
+                    issues.append(
+                        FileIssue(
+                            file=str(path),
+                            line=i,
+                            severity="high",
+                            category=category,
+                            snippet=line.strip()[:200],
+                        )
+                    )
+            for category, pattern in RISKY_IAC_PATTERNS.items():
+                if pattern.search(line):
+                    issues.append(
+                        FileIssue(
+                            file=str(path),
+                            line=i,
+                            severity="medium",
+                            category=category,
+                            snippet=line.strip()[:200],
+                        )
+                    )
+
+    return issues
+
+
+def parse_args() -> argparse.Namespace:
+    parser = argparse.ArgumentParser(description="Defensive internet and cloud hygiene scanner.")
+    parser.add_argument("--url", action="append", dest="urls", default=[], help="Seed URL to crawl. Can be used multiple times.")
+    parser.add_argument("--domain", action="append", dest="domains", default=[], help="Allowed domain (example.com). Can be used multiple times.")
+    parser.add_argument("--scan-root", type=Path, default=Path("."), help="Local path to scan for cloud/IaC issues.")
+    parser.add_argument("--max-pages", type=int, default=25, help="Maximum number of pages to crawl.")
+    parser.add_argument("--timeout", type=float, default=8.0, help="HTTP timeout in seconds.")
+    parser.add_argument("--out", type=Path, default=Path("hygiene_report.json"), help="Output JSON report path.")
+    return parser.parse_args()
+
+
+def main() -> int:
+    args = parse_args()
+
+    if not args.urls and not args.scan_root:
+        raise SystemExit("Provide at least one --url and/or --scan-root.")
+
+    allowed_domains = {normalize_domain(d) for d in args.domains if d.strip()}
+    if args.urls and not allowed_domains:
+        inferred = {normalize_domain(urlparse(u).hostname or "") for u in args.urls}
+        allowed_domains = {d for d in inferred if d}
+
+    report = AuditReport(start_urls=args.urls, allowed_domains=sorted(allowed_domains))
+
+    if args.urls:
+        pages_scanned, web_issues = scan_web(
+            start_urls=args.urls,
+            allowed_domains=allowed_domains,
+            max_pages=max(1, args.max_pages),
+            timeout=max(0.5, args.timeout),
+        )
+        report.pages_scanned = pages_scanned
+        report.web_issues.extend(web_issues)
+
+    if args.scan_root:
+        report.file_issues.extend(scan_files(args.scan_root))
+
+    args.out.write_text(report.to_json(), encoding="utf-8")
+    print(f"Report written to {args.out}")
+    print(f"Pages scanned: {report.pages_scanned}")
+    print(f"Web issues: {len(report.web_issues)}")
+    print(f"File issues: {len(report.file_issues)}")
+    return 0
+
+
+if __name__ == "__main__":
+    raise SystemExit(main())
diff --git a/internet_hygiene_scanner.py b/internet_hygiene_scanner.py
new file mode 100644
index 0000000000000000000000000000000000000000..764134aae6b06af536a1b6f22a07c8e388495c9e
--- /dev/null
+++ b/internet_hygiene_scanner.py
@@ -0,0 +1,196 @@
+#!/usr/bin/env python3
+"""Internet + cloud hygiene scanner for assets you own.
+
+This script does NOT attempt to crawl the public internet. It audits a list of
+URLs you provide and a local directory (e.g., a cloud storage sync/export) for
+common hygiene issues, then can write sanitized copies of text files.
+"""
+
+from __future__ import annotations
+
+import argparse
+import concurrent.futures
+import dataclasses
+import json
+import pathlib
+import re
+from typing import Iterable
+from urllib.parse import urlparse
+from urllib.request import Request, urlopen
+
+
+SECURITY_HEADERS = [
+    "content-security-policy",
+    "strict-transport-security",
+    "x-content-type-options",
+    "x-frame-options",
+    "referrer-policy",
+]
+
+SECRET_PATTERNS = {
+    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
+    "private_key_block": re.compile(r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----"),
+    "generic_api_key": re.compile(r"\b(api|secret|token)[_-]?key\b\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{12,}"),
+    "email_address": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
+}
+
+TEXT_EXTENSIONS = {".txt", ".md", ".json", ".yaml", ".yml", ".csv", ".log", ".env", ".ini"}
+
+
+@dataclasses.dataclass
+class UrlReport:
+    url: str
+    status_code: int | None
+    issues: list[str]
+
+
+@dataclasses.dataclass
+class FileFinding:
+    path: str
+    issue_type: str
+    count: int
+
+
+def validate_urls(urls: Iterable[str]) -> list[str]:
+    validated = []
+    for url in urls:
+        parsed = urlparse(url)
+        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
+            raise ValueError(f"Invalid URL: {url}")
+        validated.append(url)
+    return validated
+
+
+def audit_url(url: str, timeout_s: int = 8) -> UrlReport:
+    issues: list[str] = []
+    status_code = None
+    request = Request(url, headers={"User-Agent": "hygiene-scanner/1.0"})
+
+    try:
+        with urlopen(request, timeout=timeout_s) as response:
+            status_code = response.getcode()
+            headers = {k.lower(): v for k, v in response.headers.items()}
+            body_bytes = response.read(800_000)
+            body = body_bytes.decode("utf-8", errors="ignore")
+    except Exception as exc:  # network and server errors
+        return UrlReport(url=url, status_code=None, issues=[f"request_failed: {exc}"])
+
+    if status_code and status_code >= 400:
+        issues.append(f"http_error_status: {status_code}")
+
+    for header in SECURITY_HEADERS:
+        if header not in headers:
+            issues.append(f"missing_header: {header}")
+
+    if "http://" in body:
+        issues.append("body_contains_http_links")
+    if "<script" in body.lower() and "integrity=" not in body.lower():
+        issues.append("scripts_without_sri_possible")
+
+    return UrlReport(url=url, status_code=status_code, issues=issues)
+
+
+def is_text_file(path: pathlib.Path) -> bool:
+    return path.suffix.lower() in TEXT_EXTENSIONS
+
+
+def scan_cloud_snapshot(root: pathlib.Path) -> tuple[list[FileFinding], dict[pathlib.Path, str]]:
+    findings: list[FileFinding] = []
+    original_text: dict[pathlib.Path, str] = {}
+
+    for path in root.rglob("*"):
+        if not path.is_file() or not is_text_file(path):
+            continue
+
+        try:
+            content = path.read_text(encoding="utf-8", errors="ignore")
+        except OSError:
+            continue
+
+        original_text[path] = content
+        for issue_type, pattern in SECRET_PATTERNS.items():
+            matches = pattern.findall(content)
+            if matches:
+                findings.append(FileFinding(path=str(path), issue_type=issue_type, count=len(matches)))
+
+    return findings, original_text
+
+
+def sanitize_text(text: str) -> str:
+    sanitized = text
+    for pattern in SECRET_PATTERNS.values():
+        sanitized = pattern.sub("[REDACTED]", sanitized)
+    return sanitized
+
+
+def write_sanitized_copy(root: pathlib.Path, target: pathlib.Path, originals: dict[pathlib.Path, str]) -> int:
+    files_written = 0
+    for src_path, content in originals.items():
+        relative = src_path.relative_to(root)
+        out_path = target / relative
+        out_path.parent.mkdir(parents=True, exist_ok=True)
+
+        cleaned = sanitize_text(content)
+        out_path.write_text(cleaned, encoding="utf-8")
+        files_written += 1
+
+    return files_written
+
+
+def build_parser() -> argparse.ArgumentParser:
+    parser = argparse.ArgumentParser(description="Audit owned web URLs and local cloud snapshots for hygiene issues.")
+    parser.add_argument("--urls", nargs="*", default=[], help="HTTP/HTTPS URLs you control.")
+    parser.add_argument("--cloud-path", type=pathlib.Path, help="Local directory to scan (e.g., cloud export/sync).")
+    parser.add_argument("--sanitize-output", type=pathlib.Path, help="Write sanitized text copies to this directory.")
+    parser.add_argument("--max-workers", type=int, default=6, help="Concurrent URL checks.")
+    parser.add_argument("--output-json", type=pathlib.Path, help="Optional JSON report output path.")
+    return parser
+
+
+def main() -> None:
+    args = build_parser().parse_args()
+
+    if not args.urls and not args.cloud_path:
+        raise SystemExit("Provide at least one of --urls or --cloud-path")
+
+    url_reports: list[UrlReport] = []
+    cloud_findings: list[FileFinding] = []
+    originals: dict[pathlib.Path, str] = {}
+
+    if args.urls:
+        urls = validate_urls(args.urls)
+        with concurrent.futures.ThreadPoolExecutor(max_workers=args.max_workers) as pool:
+            url_reports = list(pool.map(audit_url, urls))
+
+    if args.cloud_path:
+        if not args.cloud_path.exists() or not args.cloud_path.is_dir():
+            raise SystemExit(f"--cloud-path does not exist or is not a directory: {args.cloud_path}")
+        cloud_findings, originals = scan_cloud_snapshot(args.cloud_path)
+
+    if args.sanitize_output:
+        if not args.cloud_path:
+            raise SystemExit("--sanitize-output requires --cloud-path")
+        files_written = write_sanitized_copy(args.cloud_path, args.sanitize_output, originals)
+        print(f"sanitized_files_written={files_written} target={args.sanitize_output}")
+
+    report = {
+        "url_reports": [dataclasses.asdict(r) for r in url_reports],
+        "cloud_findings": [dataclasses.asdict(f) for f in cloud_findings],
+        "summary": {
+            "urls_scanned": len(url_reports),
+            "urls_with_issues": sum(bool(r.issues) for r in url_reports),
+            "files_with_findings": len({f.path for f in cloud_findings}),
+            "total_findings": len(cloud_findings),
+        },
+    }
+
+    pretty = json.dumps(report, indent=2)
+    print(pretty)
+
+    if args.output_json:
+        args.output_json.parent.mkdir(parents=True, exist_ok=True)
+        args.output_json.write_text(pretty + "\n", encoding="utf-8")
+
+
+if __name__ == "__main__":
+    main()
diff --git a/DEEP_CLEANSER_USAGE.md b/DEEP_CLEANSER_USAGE.md
new file mode 100644
index 0000000000000000000000000000000000000000..6a625768268e5544c85738ead92d5e8b6a5c38e1
--- /dev/null
+++ b/DEEP_CLEANSER_USAGE.md
@@ -0,0 +1,24 @@
+# Deep Internet + Cloud Cleanser
+
+This repository now includes `deep_internet_cleanser.py`, a **defensive** scanner that:
+
+1. Crawls only your allow-listed domains.
+2. Flags risky web indicators (obfuscated scripts, hidden iframes, insecure references).
+3. Audits a cloud inventory JSON for risky controls (public access, no encryption, no MFA delete).
+4. Produces a JSON remediation report.
+
+## Run
+
+```bash
+python3 deep_internet_cleanser.py \
+  --domain example.com \
+  --seed https://example.com \
+  --max-depth 1 \
+  --max-pages 10 \
+  --inventory-json cloud_inventory_example.json \
+  --out cleanser_report.json
+```
+
+## Important
+
+Use this only on infrastructure you own or are explicitly authorized to assess.
diff --git a/cloud_inventory_example.json b/cloud_inventory_example.json
new file mode 100644
index 0000000000000000000000000000000000000000..bb6fb8caf8b4f12d1162f8a7b1dd84e7103f202e
--- /dev/null
+++ b/cloud_inventory_example.json
@@ -0,0 +1,20 @@
+{
+  "resources": [
+    {
+      "id": "s3://logs-bucket",
+      "type": "s3",
+      "public": false,
+      "encryption": true,
+      "versioning": true,
+      "mfa_delete": false
+    },
+    {
+      "id": "s3://public-assets",
+      "type": "s3",
+      "public": true,
+      "encryption": false,
+      "versioning": false,
+      "mfa_delete": false
+    }
+  ]
+}
diff --git a/deep_internet_cleanser.py b/deep_internet_cleanser.py
new file mode 100644
index 0000000000000000000000000000000000000000..ff5a421e693bb763dc5578ec997496d105e9b153
--- /dev/null
+++ b/deep_internet_cleanser.py
@@ -0,0 +1,229 @@
+#!/usr/bin/env python3
+"""Deep internet and cloud hygiene scanner.
+
+This tool is intentionally defensive: it audits assets you control, identifies risky
+signals, and writes a remediation report. It does not perform intrusive activity.
+"""
+
+from __future__ import annotations
+
+import argparse
+import json
+import re
+import time
+from dataclasses import dataclass, asdict
+from html.parser import HTMLParser
+from pathlib import Path
+from typing import Iterable
+from urllib.parse import urljoin, urlparse
+
+from urllib.error import URLError, HTTPError
+from urllib.request import Request, urlopen
+
+
+SUSPICIOUS_PATTERNS = {
+    "inline_eval": re.compile(r"\beval\s*\(", re.IGNORECASE),
+    "document_write": re.compile(r"document\.write\s*\(", re.IGNORECASE),
+    "crypto_miner_hint": re.compile(r"coinhive|cryptonight|miner", re.IGNORECASE),
+    "obfuscated_script": re.compile(r"(?:atob\(|fromCharCode\(|unescape\()", re.IGNORECASE),
+}
+
+
+class LinkExtractor(HTMLParser):
+    """Extract absolute links from HTML."""
+
+    def __init__(self, base_url: str):
+        super().__init__()
+        self.base_url = base_url
+        self.links: set[str] = set()
+
+    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
+        if tag.lower() != "a":
+            return
+        for key, value in attrs:
+            if key.lower() == "href" and value:
+                self.links.add(urljoin(self.base_url, value))
+
+
+@dataclass
+class PageFinding:
+    url: str
+    depth: int
+    status_code: int
+    risk_score: int
+    indicators: list[str]
+
+
+@dataclass
+class CloudFinding:
+    resource_id: str
+    resource_type: str
+    risk_score: int
+    indicators: list[str]
+
+
+class DeepInternetCleanser:
+    """Scan web + cloud surfaces for hygiene issues."""
+
+    def __init__(self, allowed_domains: Iterable[str], timeout: float = 8.0):
+        self.allowed_domains = {d.lower().strip() for d in allowed_domains if d.strip()}
+        self.timeout = timeout
+
+    def _is_allowed(self, url: str) -> bool:
+        host = (urlparse(url).hostname or "").lower()
+        return any(host == d or host.endswith(f".{d}") for d in self.allowed_domains)
+
+    def _analyze_html(self, html: str) -> tuple[int, list[str]]:
+        risk = 0
+        indicators: list[str] = []
+
+        for name, pattern in SUSPICIOUS_PATTERNS.items():
+            if pattern.search(html):
+                indicators.append(name)
+                risk += 20
+
+        if "<iframe" in html.lower() and "display:none" in html.lower():
+            indicators.append("hidden_iframe")
+            risk += 20
+
+        if "http://" in html.lower():
+            indicators.append("insecure_http_reference")
+            risk += 10
+
+        return min(risk, 100), indicators
+
+    def crawl(self, seed_urls: Iterable[str], max_depth: int = 2, max_pages: int = 50) -> list[PageFinding]:
+        queue: list[tuple[str, int]] = []
+        for seed in seed_urls:
+            if self._is_allowed(seed):
+                queue.append((seed, 0))
+
+        visited: set[str] = set()
+        findings: list[PageFinding] = []
+
+        while queue and len(visited) < max_pages:
+            url, depth = queue.pop(0)
+            if url in visited or depth > max_depth:
+                continue
+            visited.add(url)
+
+            try:
+                request = Request(url, headers={"User-Agent": "DeepInternetCleanser/1.0"})
+                with urlopen(request, timeout=self.timeout) as response:
+                    status_code = getattr(response, "status", 200)
+                    content_type = response.headers.get("Content-Type", "")
+                    html = response.read(2_000_000).decode("utf-8", errors="replace")
+            except (URLError, HTTPError, TimeoutError):
+                findings.append(PageFinding(url=url, depth=depth, status_code=0, risk_score=100, indicators=["unreachable"]))
+                continue
+
+            risk, indicators = self._analyze_html(html)
+            findings.append(
+                PageFinding(
+                    url=url,
+                    depth=depth,
+                    status_code=status_code,
+                    risk_score=risk,
+                    indicators=indicators,
+                )
+            )
+
+            if "text/html" not in content_type:
+                continue
+
+            extractor = LinkExtractor(url)
+            extractor.feed(html)
+            for link in extractor.links:
+                if link not in visited and self._is_allowed(link):
+                    queue.append((link, depth + 1))
+
+            time.sleep(0.05)
+
+        return findings
+
+    def scan_cloud_inventory(self, inventory_file: Path) -> list[CloudFinding]:
+        """Scan a JSON inventory for risky cloud configs.
+
+        Expected JSON: {"resources": [{"id":..., "type":..., "public": bool,
+        "encryption": bool, "mfa_delete": bool, "versioning": bool}]}
+        """
+        data = json.loads(inventory_file.read_text())
+        findings: list[CloudFinding] = []
+
+        for resource in data.get("resources", []):
+            risk = 0
+            indicators: list[str] = []
+
+            if resource.get("public") is True:
+                indicators.append("public_exposure")
+                risk += 40
+            if resource.get("encryption") is False:
+                indicators.append("encryption_disabled")
+                risk += 30
+            if resource.get("versioning") is False:
+                indicators.append("versioning_disabled")
+                risk += 10
+            if resource.get("mfa_delete") is False:
+                indicators.append("mfa_delete_disabled")
+                risk += 20
+
+            if indicators:
+                findings.append(
+                    CloudFinding(
+                        resource_id=str(resource.get("id", "unknown")),
+                        resource_type=str(resource.get("type", "unknown")),
+                        risk_score=min(risk, 100),
+                        indicators=indicators,
+                    )
+                )
+
+        return findings
+
+
+def write_report(path: Path, web_findings: list[PageFinding], cloud_findings: list[CloudFinding]) -> None:
+    report = {
+        "summary": {
+            "web_pages_scanned": len(web_findings),
+            "cloud_resources_flagged": len(cloud_findings),
+            "high_risk_web_pages": sum(1 for f in web_findings if f.risk_score >= 70),
+            "high_risk_cloud_resources": sum(1 for f in cloud_findings if f.risk_score >= 70),
+        },
+        "web_findings": [asdict(f) for f in web_findings],
+        "cloud_findings": [asdict(f) for f in cloud_findings],
+        "recommended_actions": [
+            "Quarantine and patch web pages with risk_score >= 70.",
+            "Enforce HTTPS-only resources and remove hidden/obfuscated scripts.",
+            "Set cloud resources to private, enable encryption, versioning, and MFA delete.",
+            "Integrate report output into SIEM/SOAR for automated remediation workflows.",
+        ],
+    }
+    path.write_text(json.dumps(report, indent=2))
+
+
+def build_parser() -> argparse.ArgumentParser:
+    parser = argparse.ArgumentParser(description="Defensive deep internet + cloud hygiene scanner")
+    parser.add_argument("--domain", action="append", required=True, help="Allowed domain (repeatable)")
+    parser.add_argument("--seed", action="append", required=True, help="Seed URL (repeatable)")
+    parser.add_argument("--max-depth", type=int, default=2)
+    parser.add_argument("--max-pages", type=int, default=50)
+    parser.add_argument("--inventory-json", type=Path, help="Cloud inventory JSON file")
+    parser.add_argument("--out", type=Path, default=Path("cleanser_report.json"))
+    return parser
+
+
+def main() -> None:
+    args = build_parser().parse_args()
+
+    cleanser = DeepInternetCleanser(args.domain)
+    web_findings = cleanser.crawl(args.seed, max_depth=args.max_depth, max_pages=args.max_pages)
+
+    cloud_findings: list[CloudFinding] = []
+    if args.inventory_json:
+        cloud_findings = cleanser.scan_cloud_inventory(args.inventory_json)
+
+    write_report(args.out, web_findings, cloud_findings)
+    print(f"Report written to {args.out}")
+
+
+if __name__ == "__main__":
+    main()
import time
import random
from dataclasses import dataclass, field
from typing import Dict, List, Callable


@dataclass
class EndpointState:
    name: str
    region: str
    provider: str
    healthy: bool = True
    latency_ms: float = 0.0
    error_rate: float = 0.0
    circuit_open_until: float = 0.0
    score: float = 100.0


@dataclass
class StabilizerConfig:
    health_interval_s: int = 5
    latency_weight: float = 0.4
    error_weight: float = 0.6
    circuit_break_error_threshold: float = 0.15
    circuit_break_seconds: int = 20
    min_score_to_route: float = 30.0


class UniversalNetworkStabilizer:
    """
    A cloud-agnostic resilience controller skeleton.
    Integrate with your DNS/GSLB, service mesh, and cloud APIs.
    """

    def __init__(self, endpoints: List[EndpointState], config: StabilizerConfig):
        self.endpoints: Dict[str, EndpointState] = {e.name: e for e in endpoints}
        self.config = config
        self.remediation_hooks: List[Callable[[EndpointState], None]] = []

    def add_remediation_hook(self, hook: Callable[[EndpointState], None]) -> None:
        self.remediation_hooks.append(hook)

    def _probe_endpoint(self, ep: EndpointState) -> None:
        """
        Replace this with real probes:
        - TCP/TLS handshake checks
        - HTTP synthetic checks
        - packet loss / jitter
        - cloud-native metrics pulls
        """
        # Simulated telemetry
        ep.latency_ms = max(1, random.gauss(80, 25))
        ep.error_rate = min(max(random.gauss(0.03, 0.05), 0.0), 1.0)
        ep.healthy = ep.error_rate < 0.5

    def _compute_score(self, ep: EndpointState) -> None:
        now = time.time()
        if ep.circuit_open_until > now:
            ep.score = 0.0
            return

        latency_penalty = min(ep.latency_ms / 300.0, 1.0) * 100 * self.config.latency_weight
        error_penalty = ep.error_rate * 100 * self.config.error_weight
        health_penalty = 40.0 if not ep.healthy else 0.0
        ep.score = max(0.0, 100.0 - latency_penalty - error_penalty - health_penalty)

        if ep.error_rate >= self.config.circuit_break_error_threshold:
            ep.circuit_open_until = now + self.config.circuit_break_seconds
            ep.score = 0.0
            for hook in self.remediation_hooks:
                hook(ep)

    def evaluate(self) -> Dict[str, EndpointState]:
        for ep in self.endpoints.values():
            self._probe_endpoint(ep)
            self._compute_score(ep)
        return self.endpoints

    def choose_best_routes(self, top_n: int = 3) -> List[EndpointState]:
        candidates = [
            ep for ep in self.endpoints.values()
            if ep.score >= self.config.min_score_to_route
        ]
        candidates.sort(key=lambda e: e.score, reverse=True)
        return candidates[:top_n]

    def control_loop(self) -> None:
        while True:
            states = self.evaluate()
            best = self.choose_best_routes(top_n=3)

            print("\n=== Endpoint Scores ===")
            for ep in sorted(states.values(), key=lambda x: x.score, reverse=True):
                print(
                    f"{ep.name:20} score={ep.score:6.2f} "
                    f"lat={ep.latency_ms:6.1f}ms err={ep.error_rate:5.2%} "
                    f"circuit={'OPEN' if ep.circuit_open_until > time.time() else 'CLOSED'}"
                )

            print("\nRoute traffic to:")
            for ep in best:
                print(f"- {ep.name} ({ep.provider}/{ep.region}) score={ep.score:.2f}")

            # In production, push decisions to:
            # - GSLB / DNS weighted records
            # - Anycast steering
            # - Service mesh traffic policies
            # - Cloud load balancer weights
            time.sleep(self.config.health_interval_s)


def restart_gateway_hook(ep: EndpointState) -> None:
    print(f"[REMEDIATE] Circuit opened for {ep.name}. Triggering remediation workflow...")


if __name__ == "__main__":
    endpoints = [
        EndpointState(name="aws-us-east-1-a", region="us-east-1", provider="aws"),
        EndpointState(name="gcp-us-central1-a", region="us-central1", provider="gcp"),
        EndpointState(name="azure-eastus-a", region="eastus", provider="azure"),
        EndpointState(name="aws-eu-west-1-a", region="eu-west-1", provider="aws"),
    ]
    cfg = StabilizerConfig()
    stabilizer = UniversalNetworkStabilizer(endpoints, cfg)
    stabilizer.add_remediation_hook(restart_gateway_hook)
    stabilizer.control_loop()
          diff --git a/cloud_network_stabilizer.py b/cloud_network_stabilizer.py
new file mode 100644
index 0000000000000000000000000000000000000000..432e66f5d98562b2998ee96c7cccb121b3f199e3
--- /dev/null
+++ b/cloud_network_stabilizer.py
@@ -0,0 +1,286 @@
+"""Multi-cloud network resilience controller.
+
+This module provides a deployable foundation for improving network stability across
+AWS, GCP, and Azure by combining:
+
+1. OpenTelemetry / Prometheus style metrics ingestion
+2. DNS/GSLB traffic steering adapters
+3. Kubernetes and service mesh failover orchestration
+4. Chaos engineering simulation with SLO-driven policy tuning
+"""
+
+from __future__ import annotations
+
+from dataclasses import dataclass, field
+from datetime import datetime, timezone
+from typing import Dict, Iterable, List, Optional, Protocol
+
+
+@dataclass
+class EndpointTelemetry:
+    endpoint: str
+    latency_ms: float
+    error_rate: float
+    availability: float
+    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
+
+
+@dataclass
+class EndpointState:
+    endpoint: str
+    provider: str
+    region: str
+    score: float = 100.0
+    healthy: bool = True
+    circuit_open: bool = False
+
+
+@dataclass
+class SLOTargets:
+    max_latency_ms: float = 250.0
+    max_error_rate: float = 0.02
+    min_availability: float = 0.999
+
+
+@dataclass
+class RoutingDecision:
+    active_endpoints: List[str]
+    weights: Dict[str, int]
+    reason: str
+
+
+class MetricsSource(Protocol):
+    def fetch(self) -> Iterable[EndpointTelemetry]:
+        """Return telemetry points for endpoints."""
+
+
+class DNSProvider(Protocol):
+    name: str
+
+    def apply_weighted_routing(self, weights: Dict[str, int]) -> None:
+        """Apply weighted DNS routing across available backends."""
+
+
+class FailoverProvider(Protocol):
+    name: str
+
+    def isolate_endpoint(self, endpoint: str) -> None:
+        """Isolate unhealthy endpoint from serving path."""
+
+    def restore_endpoint(self, endpoint: str) -> None:
+        """Re-enable a healthy endpoint in serving path."""
+
+
+class PrometheusMetricsSource:
+    """Simple in-memory adapter for Prometheus-scraped values.
+
+    In a production deployment this class can be backed by Prometheus HTTP API
+    or OpenTelemetry Collector export streams.
+    """
+
+    def __init__(self, seed_data: Optional[List[EndpointTelemetry]] = None):
+        self._seed_data = seed_data or []
+
+    def fetch(self) -> Iterable[EndpointTelemetry]:
+        return list(self._seed_data)
+
+
+class Route53Adapter:
+    name = "route53"
+
+    def __init__(self):
+        self.last_weights: Dict[str, int] = {}
+
+    def apply_weighted_routing(self, weights: Dict[str, int]) -> None:
+        # Replace with boto3 route53 record updates.
+        self.last_weights = dict(weights)
+
+
+class CloudDNSAdapter:
+    name = "cloud_dns"
+
+    def __init__(self):
+        self.last_weights: Dict[str, int] = {}
+
+    def apply_weighted_routing(self, weights: Dict[str, int]) -> None:
+        # Replace with google-cloud-dns changesets.
+        self.last_weights = dict(weights)
+
+
+class AzureDNSAdapter:
+    name = "azure_dns"
+
+    def __init__(self):
+        self.last_weights: Dict[str, int] = {}
+
+    def apply_weighted_routing(self, weights: Dict[str, int]) -> None:
+        # Replace with Azure Traffic Manager profile updates.
+        self.last_weights = dict(weights)
+
+
+class KubernetesFailoverProvider:
+    name = "kubernetes"
+
+    def __init__(self):
+        self.isolated: List[str] = []
+        self.restored: List[str] = []
+
+    def isolate_endpoint(self, endpoint: str) -> None:
+        # Replace with endpoint removal / service label selectors.
+        if endpoint not in self.isolated:
+            self.isolated.append(endpoint)
+
+    def restore_endpoint(self, endpoint: str) -> None:
+        if endpoint not in self.restored:
+            self.restored.append(endpoint)
+
+
+class ServiceMeshFailoverProvider:
+    name = "service_mesh"
+
+    def __init__(self):
+        self.isolated: List[str] = []
+        self.restored: List[str] = []
+
+    def isolate_endpoint(self, endpoint: str) -> None:
+        # Replace with Istio/Linkerd traffic policy updates.
+        if endpoint not in self.isolated:
+            self.isolated.append(endpoint)
+
+    def restore_endpoint(self, endpoint: str) -> None:
+        if endpoint not in self.restored:
+            self.restored.append(endpoint)
+
+
+class MultiCloudResilienceController:
+    """Score endpoints and orchestrate failover decisions from SLOs."""
+
+    def __init__(
+        self,
+        endpoints: List[EndpointState],
+        metrics_source: MetricsSource,
+        dns_providers: List[DNSProvider],
+        failover_providers: List[FailoverProvider],
+        slo: Optional[SLOTargets] = None,
+    ):
+        self.endpoints: Dict[str, EndpointState] = {e.endpoint: e for e in endpoints}
+        self.metrics_source = metrics_source
+        self.dns_providers = dns_providers
+        self.failover_providers = failover_providers
+        self.slo = slo or SLOTargets()
+
+    def _score(self, metric: EndpointTelemetry) -> float:
+        latency_component = max(0.0, 100.0 - (metric.latency_ms / self.slo.max_latency_ms) * 40.0)
+        error_component = max(0.0, 100.0 - (metric.error_rate / max(self.slo.max_error_rate, 1e-6)) * 40.0)
+        availability_component = min(100.0, (metric.availability / self.slo.min_availability) * 20.0)
+        return max(0.0, min(100.0, latency_component + error_component + availability_component))
+
+    def _healthy(self, metric: EndpointTelemetry) -> bool:
+        return (
+            metric.latency_ms <= self.slo.max_latency_ms
+            and metric.error_rate <= self.slo.max_error_rate
+            and metric.availability >= self.slo.min_availability
+        )
+
+    def evaluate(self) -> RoutingDecision:
+        telemetry = list(self.metrics_source.fetch())
+        if not telemetry:
+            return RoutingDecision([], {}, "no_telemetry")
+
+        for point in telemetry:
+            state = self.endpoints.get(point.endpoint)
+            if not state:
+                continue
+            state.score = self._score(point)
+            state.healthy = self._healthy(point)
+            state.circuit_open = not state.healthy
+
+        healthy = [e for e in self.endpoints.values() if e.healthy]
+        healthy.sort(key=lambda x: x.score, reverse=True)
+
+        if not healthy:
+            return RoutingDecision([], {}, "global_degradation")
+
+        weights = self._weights(healthy)
+        active = [e.endpoint for e in healthy]
+        return RoutingDecision(active, weights, "slo_weighted_routing")
+
+    def _weights(self, healthy_endpoints: List[EndpointState]) -> Dict[str, int]:
+        total = sum(max(1.0, e.score) for e in healthy_endpoints)
+        output: Dict[str, int] = {}
+        for endpoint in healthy_endpoints:
+            output[endpoint.endpoint] = max(1, int(round((endpoint.score / total) * 100)))
+        return output
+
+    def apply(self, decision: RoutingDecision) -> None:
+        for provider in self.dns_providers:
+            provider.apply_weighted_routing(decision.weights)
+
+        active = set(decision.active_endpoints)
+        for endpoint in self.endpoints.values():
+            for provider in self.failover_providers:
+                if endpoint.endpoint in active:
+                    provider.restore_endpoint(endpoint.endpoint)
+                else:
+                    provider.isolate_endpoint(endpoint.endpoint)
+
+
+class ChaosTestHarness:
+    """Inject faults into telemetry and measure resilience policy outcomes."""
+
+    def __init__(self, controller: MultiCloudResilienceController):
+        self.controller = controller
+
+    def run_latency_spike(self, endpoint: str, spike_ms: float) -> RoutingDecision:
+        seeded = []
+        for t in self.controller.metrics_source.fetch():
+            if t.endpoint == endpoint:
+                seeded.append(
+                    EndpointTelemetry(
+                        endpoint=t.endpoint,
+                        latency_ms=t.latency_ms + spike_ms,
+                        error_rate=t.error_rate,
+                        availability=t.availability,
+                    )
+                )
+            else:
+                seeded.append(t)
+
+        self.controller.metrics_source = PrometheusMetricsSource(seeded)
+        decision = self.controller.evaluate()
+        self.controller.apply(decision)
+        return decision
+
+    def tune_slo(self, max_latency_ms: Optional[float] = None, max_error_rate: Optional[float] = None) -> SLOTargets:
+        if max_latency_ms is not None:
+            self.controller.slo.max_latency_ms = max_latency_ms
+        if max_error_rate is not None:
+            self.controller.slo.max_error_rate = max_error_rate
+        return self.controller.slo
+
+
+if __name__ == "__main__":
+    telemetry = [
+        EndpointTelemetry("aws-us-east-1", latency_ms=90, error_rate=0.01, availability=0.9995),
+        EndpointTelemetry("gcp-us-central1", latency_ms=120, error_rate=0.015, availability=0.9991),
+        EndpointTelemetry("azure-eastus", latency_ms=180, error_rate=0.03, availability=0.9982),
+    ]
+
+    controller = MultiCloudResilienceController(
+        endpoints=[
+            EndpointState("aws-us-east-1", provider="aws", region="us-east-1"),
+            EndpointState("gcp-us-central1", provider="gcp", region="us-central1"),
+            EndpointState("azure-eastus", provider="azure", region="eastus"),
+        ],
+        metrics_source=PrometheusMetricsSource(telemetry),
+        dns_providers=[Route53Adapter(), CloudDNSAdapter(), AzureDNSAdapter()],
+        failover_providers=[KubernetesFailoverProvider(), ServiceMeshFailoverProvider()],
+    )
+
+    baseline = controller.evaluate()
+    controller.apply(baseline)
+    print("Baseline:", baseline)
+
+    chaos = ChaosTestHarness(controller)
+    chaos_decision = chaos.run_latency_spike("aws-us-east-1", spike_ms=400)
+    print("After chaos spike:", chaos_decision)

        diff --git a/tests/test_cloud_network_stabilizer.py b/tests/test_cloud_network_stabilizer.py
new file mode 100644
index 0000000000000000000000000000000000000000..3fe95caf413c0abd289703bb461e35bb6e6aeef1
--- /dev/null
+++ b/tests/test_cloud_network_stabilizer.py
@@ -0,0 +1,57 @@
+from cloud_network_stabilizer import (
+    AzureDNSAdapter,
+    ChaosTestHarness,
+    CloudDNSAdapter,
+    EndpointState,
+    EndpointTelemetry,
+    KubernetesFailoverProvider,
+    MultiCloudResilienceController,
+    PrometheusMetricsSource,
+    Route53Adapter,
+    ServiceMeshFailoverProvider,
+)
+
+
+def build_controller(telemetry):
+    return MultiCloudResilienceController(
+        endpoints=[
+            EndpointState("aws-us-east-1", provider="aws", region="us-east-1"),
+            EndpointState("gcp-us-central1", provider="gcp", region="us-central1"),
+        ],
+        metrics_source=PrometheusMetricsSource(telemetry),
+        dns_providers=[Route53Adapter(), CloudDNSAdapter(), AzureDNSAdapter()],
+        failover_providers=[KubernetesFailoverProvider(), ServiceMeshFailoverProvider()],
+    )
+
+
+def test_routes_only_healthy_endpoints():
+    controller = build_controller(
+        [
+            EndpointTelemetry("aws-us-east-1", latency_ms=100, error_rate=0.01, availability=0.9995),
+            EndpointTelemetry("gcp-us-central1", latency_ms=400, error_rate=0.03, availability=0.9980),
+        ]
+    )
+
+    decision = controller.evaluate()
+    controller.apply(decision)
+
+    assert decision.active_endpoints == ["aws-us-east-1"]
+    assert decision.weights["aws-us-east-1"] >= 1
+
+
+def test_chaos_latency_spike_rebalances_traffic():
+    controller = build_controller(
+        [
+            EndpointTelemetry("aws-us-east-1", latency_ms=80, error_rate=0.01, availability=0.9999),
+            EndpointTelemetry("gcp-us-central1", latency_ms=90, error_rate=0.01, availability=0.9999),
+        ]
+    )
+
+    baseline = controller.evaluate()
+    assert set(baseline.active_endpoints) == {"aws-us-east-1", "gcp-us-central1"}
+
+    harness = ChaosTestHarness(controller)
+    post_chaos = harness.run_latency_spike("aws-us-east-1", spike_ms=500)
+
+    assert "gcp-us-central1" in post_chaos.active_endpoints
+    assert "aws-us-east-1" not in post_chaos.active_endpoints
