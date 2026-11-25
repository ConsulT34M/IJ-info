# A사 비대면 본인확인 대행 (실습용)

SK쉴더스 루키즈 보안컨설팅 트랙 최종 프로젝트. 위탁사(가상자산 거래소)의 비대면 본인확인을
대행하는 수탁사 A사 시스템이다. 금융보안원 금융분야 취약점 분석·평가 기준 + ISMS-P로
**설정 점검 수준**의 진단을 하기 위해 만든다.

- 기준 명세: [CLAUDE.md](CLAUDE.md)
- 설계 결정 기록: [docs/DECISIONS.md](docs/DECISIONS.md)
- **격리된 실습 환경 전용.** 실제 개인정보를 쓰지 않는다. 가상 인물 10명(고정 시드),
  체크섬만 맞춘 가상 주민번호, 가짜 휴대폰번호만 쓴다.
- 기본값은 전부 양호(안전)다. 진단 연습용 취약 동작은 `VULN_*` 플래그를 켤 때만 나온다.

## 준비

```bash
uv python install 3.11
uv venv --python 3.11
uv pip install -r requirements.txt
```

## 로컬 실행

```bash
cp .env.example .env                   # FLASK_APP=app, EKYC_ENV=dev, 취약 플래그 전부 false
docker compose up -d                   # PostgreSQL 16 (127.0.0.1:5432에만 바인딩)
.venv/bin/python seed/make_people.py   # 가상 인물 10명 → seed/people.json (마스킹 요약만 출력)
.venv/bin/flask db upgrade             # 13개 테이블 생성
.venv/bin/flask seed                   # 개발용 시크릿 + 진위확인 대장 + 테스트 수신함 적재
.venv/bin/flask run                    # http://127.0.0.1:8000/healthz (D38)
```

위탁사·관리자 등록 (API Key·HMAC Secret·TOTP URI는 **생성 시 한 번만** 출력된다):

```bash
.venv/bin/flask create-client --name "SILO 거래소"   --callback-url http://127.0.0.1:9000/callback --allowed-ips 127.0.0.1
.venv/bin/flask create-admin --login-id admin1 --role admin --allowed-ips 127.0.0.1
```

## 인증 흐름 확인 (가짜 거래소)

`tools/fake_exchange.py`는 거래소 담당에게 넘기는 서명 구현 예시다. A사 코드를 import하지 않는다.

```bash
# create-client가 출력한 값을 넣는다
export EKYC_API_KEY=... EKYC_HMAC_SECRET=...

.venv/bin/python tools/fake_exchange.py serve     # 터미널 1: 웹훅 수신·서명 검증
.venv/bin/python tools/fake_exchange.py request --client-user-ref user-0001   # 터미널 2
# 출력된 auth_url을 브라우저에서 연다 → 동의 → 휴대폰 입력 화면
.venv/bin/python tools/fake_exchange.py query <verification_id>               # IA-12 (6단계)
```

## 테스트

```bash
.venv/bin/python -m pytest -q                     # SQLite 메모리 (docker 없이도 돈다)

# PostgreSQL로 돌리기 (별도 테스트 DB). @pytest.mark.postgres 테스트도 함께 돈다
docker compose exec -T db psql -U ekyc -d postgres -c "CREATE DATABASE ekyc_test OWNER ekyc;"
TEST_DATABASE_URL=postgresql+psycopg://ekyc:ekyc@127.0.0.1:5432/ekyc_test \
  .venv/bin/python -m pytest -q
```

`seed/people.json`, `instance/`, 인증서, 업로드 파일은 커밋하지 않는다(.gitignore).
