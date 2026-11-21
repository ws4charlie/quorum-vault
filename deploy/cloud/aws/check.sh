#!/usr/bin/env bash
# Every check of the AWS reference deployment that needs no account, no credentials and no network call to AWS. CI (.github/workflows/terraform.yml) and people run the same file.
#   deploy/cloud/aws/check.sh            all checks
#   deploy/cloud/aws/check.sh fmt        one step: fmt | validate | test | lint | scan | values | nitro | creds
# Needs on PATH: helm, python3 with PyYAML (requirements.txt), terraform (the version pinned in the workflow), tflint (with `tflint --init` done), trivy. The provider is downloaded from the public registry by `init`; nothing talks to AWS.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here" || exit 2
step="${1:-all}"
bad=0

# No credentials, no instance-metadata lookup: if anything tried to reach AWS it would fail instead of succeeding quietly.
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE AWS_WEB_IDENTITY_TOKEN_FILE AWS_ROLE_ARN
export AWS_EC2_METADATA_DISABLED=true TF_IN_AUTOMATION=1 TF_INPUT=0

want() { [ "$step" = all ] || [ "$step" = "$1" ]; }
fail() { bad=1; echo "FAIL: $*"; }

dirs_with_tf() { find "$@" -mindepth 1 -maxdepth 1 -type d | sort; }
modules="$(dirs_with_tf modules)"
roots="$(dirs_with_tf roots)"

if want fmt; then
  echo "== terraform fmt -check"
  terraform fmt -check -recursive -diff . || fail "terraform fmt"
fi

init_dir() { (cd "$1" && terraform init -backend=false -input=false -no-color >/dev/null) || { fail "init $1"; return 1; }; }

if want validate; then
  echo "== terraform init -backend=false and validate (every root)"
  for d in $roots; do
    init_dir "$d" || continue
    (cd "$d" && terraform validate -no-color) || fail "validate $d"
  done
  for d in $modules; do
    init_dir "$d" || continue
    (cd "$d" && terraform validate -no-color) || fail "validate $d"
  done
fi

if want test; then
  echo "== terraform test (mocked provider, no account)"
  for d in $modules $roots; do
    # a module or root without tests is a failure, never a pass
    [ -n "$(find "$d/tests" -name '*.tftest.hcl' 2>/dev/null | head -1)" ] || { fail "no terraform test in $d"; continue; }
    init_dir "$d" || continue
    (cd "$d" && terraform test -no-color) || fail "terraform test $d"
  done
fi

if want lint; then
  echo "== tflint"
  for d in $modules $roots; do
    tflint --chdir="$d" --config="$here/.tflint.hcl" -f compact --minimum-failure-severity=warning || fail "tflint $d"
  done
fi

if want scan; then
  echo "== trivy config (suppressions, each with its reason: .trivyignore.yaml)"
  trivy config --skip-version-check --quiet --severity LOW,MEDIUM,HIGH,CRITICAL --ignorefile .trivyignore.yaml --exit-code 1 . || fail "trivy config"
fi

if want values; then
  echo "== chart values for the AWS shape: keys exist, and the rendered NetworkPolicies cover every path of paths.json and nothing else"
  # helm and PyYAML are required: a missing tool is a failure (the workflow installs PyYAML from requirements.txt, pinned)
  command -v helm >/dev/null || { fail "helm is not installed"; }
  python3 -c 'import yaml' 2>/dev/null || { fail "PyYAML is not installed (pip install -r deploy/cloud/aws/requirements.txt)"; }
  python3 values/values_test.py || fail "values (keys exist in the charts)"
  python3 values/render_test.py || fail "values (rendered NetworkPolicies match paths.json)"
fi

if want nitro; then
  echo "== the Nitro helper scripts (nitro-cli output to allowlist command, allowlist to key-policy variable)"
  python3 nitro/nitro_test.py || fail "nitro scripts"
fi

if want creds; then
  echo "== nothing in the workflow or here can reach AWS"
  wf="$here/../../../.github/workflows/terraform.yml"
  if grep -nE 'id-token|aws-actions|configure-aws-credentials|AWS_(ACCESS|SECRET|SESSION|ROLE)|role-to-assume|secrets\.' "$wf"; then fail "the terraform workflow names a credential, a role or a secret"; fi
  # a provider alias or an assume_role in code would be a path to another account
  if grep -rnE '\bassume_role\b|\baccess_key\b|\bsecret_key\b|shared_credentials' --include='*.tf' .; then fail "a .tf file names credentials or a role to assume"; fi
fi

[ "$bad" = 0 ] && echo "all checks passed" || echo "CHECKS FAILED"
exit "$bad"
