#!/usr/bin/env bash
# 시연 환경을 처음 상태로 되돌린다. 몇 번이고 다시 돌릴 수 있다.
#
#   bash tools/demo_reset.sh          # 확인 후 진행
#   bash tools/demo_reset.sh -y       # 확인 없이 진행
#   bash tools/demo_reset.sh -y --regen-people   # 가상 인물도 다시 생성
#
# 하는 일: DB 초기화 → 마이그레이션 → flask seed → 통신사 인증서·명부 →
#          가짜 거래소 고객사 등록 → 관리자 2명 생성 → 샘플 이미지 생성
#
# 주의: A사 PostgreSQL의 public 스키마를 지운다. 격리된 실습 환경 전용이다.

set -euo pipefail
cd "$(dirname "$0")/.."

PY=.venv/bin/python
FLASK=.venv/bin/flask
export FLASK_APP=app
ASSUME_YES=0
REGEN_PEOPLE=0

for arg in "$@"; do
  case "$arg" in
    -y|--yes) ASSUME_YES=1 ;;
    --regen-people) REGEN_PEOPLE=1 ;;
    *) echo "모르는 옵션: $arg" >&2; exit 2 ;;
  esac
done

step() { printf '\n==> %s\n' "$1"; }
fail() { printf '오류: %s\n' "$1" >&2; exit 1; }

[ -x "$PY" ] || fail "$PY 가 없다. uv venv --python 3.11 && uv pip install -r requirements.txt 를 먼저 한다."
command -v docker >/dev/null || fail "docker가 필요하다."
docker info >/dev/null 2>&1 || fail "docker 데몬이 꺼져 있다. Docker Desktop을 먼저 띄운다."

if [ "$ASSUME_YES" -ne 1 ]; then
  printf 'A사 DB(public 스키마)와 통신사 SQLite를 지우고 처음 상태로 만든다. 계속할까? [y/N] '
  read -r answer
  case "$answer" in y|Y|yes|YES) ;; *) echo "취소했다."; exit 0 ;; esac
fi

step "컨테이너 기동 (Apache · Gunicorn · PostgreSQL)"
# 웹서버 인증서가 없으면 web 컨테이너가 뜨지 않는다. 처음 한 번만 만들어진다.
mkdir -p instance
bash ops/make_web_certs.sh | tail -n 1
docker compose up -d --build >/dev/null
for _ in $(seq 1 30); do
  if docker compose exec -T db pg_isready -U ekyc -d ekyc >/dev/null 2>&1; then break; fi
  sleep 1
done
docker compose exec -T db pg_isready -U ekyc -d ekyc >/dev/null || fail "PostgreSQL이 준비되지 않았다."
echo "준비됨"

step "A사 DB 초기화"
docker compose exec -T db psql -U ekyc -d ekyc -q \
  -c "DROP SCHEMA public CASCADE;" -c "CREATE SCHEMA public;" \
  -c "GRANT ALL ON SCHEMA public TO ekyc;"
echo "public 스키마를 다시 만들었다"

step "마이그레이션 적용"
$FLASK db upgrade 2>&1 | grep -E "Running upgrade|already" || true
TABLES=$(docker compose exec -T db psql -U ekyc -d ekyc -tAc \
  "select count(*) from information_schema.tables where table_schema='public';")
echo "테이블 ${TABLES}개 (13 + alembic_version)"

step "가상 인물"
if [ "$REGEN_PEOPLE" -eq 1 ]; then
  $PY seed/make_people.py | tail -n 12
elif [ -f samples/people.json ]; then
  cp samples/people.json seed/people.json
  chmod 600 seed/people.json
  echo "samples/people.json 을 쓴다 (팀원 모두 같은 10명). --regen-people 로 새로 뽑는다"
elif [ ! -f seed/people.json ]; then
  $PY seed/make_people.py | tail -n 12
else
  echo "seed/people.json 을 그대로 쓴다"
fi

step "A사 적재 (시크릿 + 진위확인 대장 + 테스트 수신함)"
$FLASK seed | head -n 3
$FLASK seed-library | tail -n 1

step "모의 통신사"
if [ ! -f carrier/certs/carrier.crt ]; then
  $PY -m carrier.make_certs | head -n 1
else
  echo "carrier/certs/carrier.crt 를 그대로 쓴다"
fi
rm -f carrier/instance/carrier.sqlite3
$PY -m carrier.seed | head -n 2

step "가짜 거래소 고객사 등록"
mkdir -p instance
CLIENT_OUT=$($FLASK create-client \
  --name "SILO 거래소" \
  --callback-url "http://127.0.0.1:9000/callback" \
  --allowed-ips "127.0.0.1")
API_KEY=$(printf '%s\n' "$CLIENT_OUT" | awk -F': ' '/X-Api-Key/{print $2}')
HMAC_SECRET=$(printf '%s\n' "$CLIENT_OUT" | awk -F': ' '/HMAC Secret/{print $2}')
CLIENT_ID=$(printf '%s\n' "$CLIENT_OUT" | awk -F': ' '/client_id/{print $2}')
[ -n "$API_KEY" ] && [ -n "$HMAC_SECRET" ] || fail "API Key·HMAC Secret을 읽지 못했다."

umask 077
cat > instance/fake_exchange.env <<EOF
# tools/fake_exchange.py 용 환경변수 (커밋 금지)
# source instance/fake_exchange.env
export EKYC_API_KEY=$API_KEY
export EKYC_HMAC_SECRET=$HMAC_SECRET
export EKYC_BASE_URL=http://127.0.0.1:8000
# client_id=$CLIENT_ID
EOF
chmod 600 instance/fake_exchange.env
echo "instance/fake_exchange.env 에 저장했다 (권한 600)"

step "관리자 2명 생성"
ADMIN_PW=$($PY -c "import secrets;print('Demo!'+secrets.token_urlsafe(12))")
AUDITOR_PW=$($PY -c "import secrets;print('Demo!'+secrets.token_urlsafe(12))")

admin_uri() {
  printf '%s\n' "$2" | $FLASK create-admin --login-id "$1" --role "$3" \
    --allowed-ips "127.0.0.1" --password-stdin | awk '/otpauth:\/\//{print $1}'
}
ADMIN_URI=$(admin_uri admin1 "$ADMIN_PW" admin)
AUDITOR_URI=$(admin_uri auditor1 "$AUDITOR_PW" auditor)
ADMIN_SECRET=$(printf '%s' "$ADMIN_URI" | sed -n 's/.*secret=\([A-Z2-7]*\).*/\1/p')
AUDITOR_SECRET=$(printf '%s' "$AUDITOR_URI" | sed -n 's/.*secret=\([A-Z2-7]*\).*/\1/p')
[ -n "$ADMIN_SECRET" ] && [ -n "$AUDITOR_SECRET" ] || fail "TOTP 시크릿을 읽지 못했다."

cat > instance/demo_admins.env <<EOF
# 관리자 시연 계정 (커밋 금지)
# source instance/demo_admins.env
export ADMIN1_LOGIN_ID=admin1
export ADMIN1_PASSWORD=$ADMIN_PW
export ADMIN1_TOTP_SECRET=$ADMIN_SECRET
export AUDITOR1_LOGIN_ID=auditor1
export AUDITOR1_PASSWORD=$AUDITOR_PW
export AUDITOR1_TOTP_SECRET=$AUDITOR_SECRET
EOF
chmod 600 instance/demo_admins.env
echo "instance/demo_admins.env 에 저장했다 (권한 600)"

step "샘플 이미지"
$PY tools/make_sample_images.py --extras | head -n 1

cat <<EOF

────────────────────────────────────────────────────────────────────────
초기화를 마쳤다.

[관리자 계정]
  admin1   (admin)    비밀번호: $ADMIN_PW
  auditor1 (auditor)  비밀번호: $AUDITOR_PW

  TOTP 등록 URI (인증 앱에 넣는다):
    $ADMIN_URI
    $AUDITOR_URI

  지금 코드 보기:
    source instance/demo_admins.env && .venv/bin/python -c "import os,pyotp; \\
      print('admin1  ', pyotp.TOTP(os.environ['ADMIN1_TOTP_SECRET']).now()); \\
      print('auditor1', pyotp.TOTP(os.environ['AUDITOR1_TOTP_SECRET']).now())"

[가짜 거래소]
  source instance/fake_exchange.env   # EKYC_API_KEY / EKYC_HMAC_SECRET

[모의 PASS 앱]  인증번호를 받는 자리다. 수신함 키를 복붙하지 않는다.
  .venv/bin/python tools/pass_app.py register   # 번호·성명·생년월일을 물어본다
  .venv/bin/python tools/pass_app.py watch      # 문자가 오면 화면에 뜬다
  기기 등록은 초기화할 때마다 다시 한다(수신함 키가 seed 값으로 돌아간다).

[웹 서비스]  두 가지 방법 중 하나로 연다.
  운영 형태(진단 대상):  https://localhost:9443      ← 컨테이너가 이미 떠 있다
                          Apache → Gunicorn → Flask. 자체 서명이라 경고가 뜬다.
  개발 형태(코드 수정):  .venv/bin/flask run         → http://127.0.0.1:8000

  웹서버 양호/취약 전환:  ops/apply_vuln.sh · ops/revert_vuln.sh

다음: docs/DEMO.md 의 "터미널 3개" 대로 띄운다.
────────────────────────────────────────────────────────────────────────
EOF
