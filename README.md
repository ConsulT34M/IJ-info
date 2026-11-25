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

## 1단계까지 쓸 수 있는 것

```bash
.venv/bin/python seed/make_people.py   # 가상 인물 10명 → seed/people.json (마스킹 요약만 출력)
.venv/bin/python -m pytest -q          # 단위 테스트
```

`seed/people.json`, `instance/`, 인증서, 업로드 파일은 커밋하지 않는다(.gitignore).
