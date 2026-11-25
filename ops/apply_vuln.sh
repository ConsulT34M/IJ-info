#!/usr/bin/env bash
# 웹서버(Apache) 설정을 **의도된 취약**으로 바꾼다. 실습 전용이다.
#
#   ops/apply_vuln.sh        취약 설정 적용
#   ops/revert_vuln.sh       양호 설정으로 되돌림
#
# 앱 코드 쪽 취약은 VULN_* 환경변수로 따로 켠다(.env 또는 compose environment).
set -euo pipefail
cd "$(dirname "$0")/.."

cp ops/apache/ekyc-vuln.conf ops/apache/active.conf
echo "웹서버 설정을 취약으로 바꿨다: ops/apache/active.conf ← ekyc-vuln.conf"
echo
echo "무엇이 달라졌는지:"
diff -u ops/apache/ekyc-good.conf ops/apache/ekyc-vuln.conf | grep -E '^\+[^+]' | sed 's/^+/  /' || true
echo
if docker compose ps --services --status running 2>/dev/null | grep -qx web; then
  docker compose restart web >/dev/null
  echo "web 컨테이너를 다시 올렸다."
else
  echo "web 컨테이너가 떠 있지 않다. docker compose up -d 로 올린다."
fi
