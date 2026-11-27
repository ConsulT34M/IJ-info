#!/usr/bin/env bash
# Apache용 로컬 자체 서명 인증서를 만든다. ops/certs/ 는 gitignore 대상이다.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=ops/certs
mkdir -p "$OUT"

if [ -f "$OUT/web.crt" ] && [ "${1:-}" != "--force" ]; then
  echo "이미 있다: $OUT/web.crt  (다시 만들려면 --force)"
  exit 0
fi

# 인증서 이름은 WEB_SERVER_NAME(환경변수 → .env → localhost 순)에서 읽는다.
HOST="${WEB_SERVER_NAME:-}"
if [ -z "$HOST" ] && [ -f .env ]; then
  HOST="$(grep -E '^WEB_SERVER_NAME=' .env | tail -n 1 | cut -d= -f2- | tr -d '\r"' || true)"
fi
HOST="${HOST:-localhost}"
case "$HOST" in
  *[!A-Za-z0-9.-]*) echo "WEB_SERVER_NAME 형식이 올바르지 않다: $HOST" >&2; exit 2 ;;
esac
SAN="DNS:localhost,IP:127.0.0.1"
[ "$HOST" = "localhost" ] || SAN="DNS:$HOST,$SAN"

openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
  -keyout "$OUT/web.key" -out "$OUT/web.crt" \
  -subj "/C=KR/O=ij-info-lab/CN=$HOST" \
  -addext "subjectAltName=$SAN" 2>/dev/null

chmod 600 "$OUT/web.key"
chmod 644 "$OUT/web.crt"
echo "웹서버 인증서를 만들었다: $OUT/web.crt (자체 서명, 로컬 전용)"
