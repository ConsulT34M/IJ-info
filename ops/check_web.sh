#!/usr/bin/env bash
# 웹서버 설정이 **실제로 동작하는지** 확인한다.
#
#   ops/check_web.sh          양호 기준으로 점검 (기본)
#   ops/check_web.sh --vuln   취약 설정일 때의 기대값으로 점검
#
# 왜 필요한가: 설정 파일에 지시어가 있다고 그게 먹는다는 보장이 없다.
# 실제로 <Location "/"> 하나가 vhost 전체의 인가 규칙을 조용히 지우고 있었고,
# 설정만 읽어서는 보이지 않았다(D95). 그 뒤로는 **설정마다 요청을 보내 확인**한다.
set -uo pipefail
cd "$(dirname "$0")/.."

MODE="good"
[ "${1:-}" = "--vuln" ] && MODE="vuln"

# 포트를 .env 에서 바꿨으면 같은 값을 환경변수로 넘긴다(예: WEB_HTTPS_PORT=443 ops/check_web.sh).
BASE_HTTPS="${CHECK_BASE_HTTPS:-https://127.0.0.1:${WEB_HTTPS_PORT:-9443}}"
BASE_HTTP="${CHECK_BASE_HTTP:-http://127.0.0.1:${WEB_HTTP_PORT:-9080}}"
PROBE_FILE="app/static/.ekyc-check.env"

if ! curl -sk -o /dev/null --max-time 3 "$BASE_HTTPS/"; then
  echo "웹서버에 연결할 수 없다: $BASE_HTTPS"
  echo "  docker compose up -d  로 먼저 올린다."
  exit 2
fi

printf 'probe\n' > "$PROBE_FILE"
trap 'rm -f "$PROBE_FILE"' EXIT

pass=0; fail=0
check() { # 이름, 기대값, 실제값
  if [ "$2" = "$3" ]; then
    printf '  \033[32m○\033[0m %-26s %s\n' "$1" "$3"; pass=$((pass+1))
  else
    printf '  \033[31m×\033[0m %-26s %s  (기대 %s)\n' "$1" "$3" "$2"; fail=$((fail+1))
  fi
}
code()   { curl -sk -o /dev/null -w '%{http_code}' ${2:+-X "$2"} "$1"; }
header() { curl -sk -I "$1" | grep -ic "$2" | tr -d ' '; }

echo
echo "웹서버 점검 — $MODE 기준  ($BASE_HTTPS)"
echo

if [ "$MODE" = "good" ]; then
  check "디렉터리 목록 차단"      403 "$(code "$BASE_HTTPS/static/")"
  check "숨김 파일 차단"          403 "$(code "$BASE_HTTPS/static/.ekyc-check.env")"
  check "정적 파일 제공"          200 "$(code "$BASE_HTTPS/static/app.css")"
  check "앱으로 프록시"           200 "$(code "$BASE_HTTPS/")"
  # TraceEnable Off 는 405(Method Not Allowed)를 낸다. 403이 아니다.
  check "TRACE 차단"              405 "$(code "$BASE_HTTPS/static/app.css" TRACE)"
  check "http → https"            301 "$(code "$BASE_HTTP/")"
  check "HSTS 헤더"                 1 "$(header "$BASE_HTTPS/" 'strict-transport')"
  check "에러에 버전 미노출"         0 "$(curl -sk "$BASE_HTTPS/static/none.css" | grep -coE 'Apache/[0-9]')"
  check "백엔드 Server 헤더 제거"    0 "$(header "$BASE_HTTPS/" '^server: gunicorn')"
else
  check "디렉터리 목록 노출"      200 "$(code "$BASE_HTTPS/static/")"
  check "숨김 파일 노출"          200 "$(code "$BASE_HTTPS/static/.ekyc-check.env")"
  check "TRACE 허용"              200 "$(code "$BASE_HTTPS/static/app.css" TRACE)"
  check "http 평문 서비스"        200 "$(code "$BASE_HTTP/")"
  check "HSTS 없음"                 0 "$(header "$BASE_HTTPS/" 'strict-transport')"
  check "에러에 버전 노출"           1 "$(curl -sk "$BASE_HTTPS/static/none.css" | grep -coE 'Apache/[0-9]')"
  check "백엔드 Server 헤더 노출"    1 "$(header "$BASE_HTTPS/" '^server: gunicorn')"
fi

echo
echo "  통과 $pass · 실패 $fail"
[ "$fail" -eq 0 ] || { echo "  설정이 기대대로 동작하지 않는다. 설정 파일을 읽기 전에 이 결과를 믿는다."; exit 1; }
