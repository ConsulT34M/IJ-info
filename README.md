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
.venv/bin/flask run                    # http://127.0.0.1:5000/healthz
```

위탁사·관리자 등록 (API Key·HMAC Secret·TOTP URI는 **생성 시 한 번만** 출력된다):

```bash
.venv/bin/flask create-client --name "SILO 거래소"   --callback-url http://127.0.0.1:9000/callback --allowed-ips 127.0.0.1
.venv/bin/flask create-admin --login-id admin1 --role admin --allowed-ips 127.0.0.1
```

## 테스트

```bash
.venv/bin/python -m pytest -q   # DB는 SQLite 메모리를 쓴다(docker 없이도 돈다)
```

`seed/people.json`, `instance/`, 인증서, 업로드 파일은 커밋하지 않는다(.gitignore).
