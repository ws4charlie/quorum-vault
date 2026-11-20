#!/usr/bin/env bash
# Copies monitoring/*.rules.yml into deploy/helm/qv-monitoring/rules/ (a chart can read only its own directory). The files of monitoring/ stay the source; ci/helm
# (monitoring_test.go) fails when a copy differs or is missing. Run this after you change a rule, then commit both.
set -euo pipefail
cd "$(dirname "$0")/../.."
dst=deploy/helm/qv-monitoring/rules
mkdir -p "$dst"
find "$dst" -name '*.rules.yml' -delete
cp monitoring/*.rules.yml "$dst/"
echo "synced $(ls "$dst" | wc -l | tr -d ' ') rule files to $dst"
