#!/usr/bin/env bash
set -euo pipefail

mode="${1:-baseline}"
target="${ZAP_TARGET_URL:-http://host.docker.internal:3000}"
image="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"
project_root="$(cd "$(dirname "$0")/.." && pwd)"
output_dir="${project_root}/outputs/zap"

case "${mode}" in
  baseline|active) ;;
  *) echo "usage: $0 baseline|active" >&2; exit 64 ;;
esac

case "${target}" in
  http://localhost:*|http://127.0.0.1:*|http://host.docker.internal:*) ;;
  https://*.chatgpt.site)
    if [[ "${mode}" == "active" ]]; then
      echo "active scans are restricted to localhost test targets" >&2
      exit 65
    fi
    ;;
  *) echo "target is not in the SAFER ZAP allowlist" >&2; exit 65 ;;
esac

mkdir -p "${output_dir}"

common=(
  --rm
  --add-host=host.docker.internal:host-gateway
  -v "${output_dir}:/zap/wrk/:rw"
  -v "${project_root}/security/zap:/zap/config:ro"
  -t "${image}"
)

if [[ "${mode}" == "baseline" ]]; then
  scan=(docker run "${common[@]}" zap-baseline.py)
  scan+=(-t "${target}" -c /zap/config/rules.conf -i -j -m 1 -T 10)
  scan+=(-r safer-zap-baseline.html -J safer-zap-baseline.json)
else
  if [[ "${ZAP_ALLOW_ACTIVE_SCAN:-}" != "local-only" ]]; then
    echo "set ZAP_ALLOW_ACTIVE_SCAN=local-only to authorize the localhost attack scan" >&2
    exit 66
  fi
  scan=(docker run "${common[@]}" zap-full-scan.py)
  scan+=(-t "${target}" -c /zap/config/rules.conf -i -j -m 2 -T 15)
  scan+=(-r safer-zap-active.html -J safer-zap-active.json)
fi

"${scan[@]}"
