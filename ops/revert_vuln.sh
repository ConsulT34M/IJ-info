#!/usr/bin/env bash
# 웹서버(Apache) 설정을 양호 기준으로 되돌린다.
set -euo pipefail
cd "$(dirname "$0")/.."

cp ops/apache/ekyc-good.conf ops/apache/active.conf
echo "웹서버 설정을 양호로 되돌렸다: ops/apache/active.conf ← ekyc-good.conf"
if docker compose ps --services --status running 2>/dev/null | grep -qx web; then
  docker compose restart web >/dev/null
  echo "web 컨테이너를 다시 올렸다."
fi
