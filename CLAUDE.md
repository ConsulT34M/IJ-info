# A사 비대면 본인확인 대행 (휴대폰 본인확인 → 얼굴인증 eKYC) — 실습용 구현 명세

이 파일이 이 저장소의 기준 명세다. 코딩 전에 끝까지 읽는다.
기준 문서는 팀 노션 「인증 수탁사 통합 (휴대폰 → 얼굴인증)」 5종이다. 이 파일은 그 내용에 아래 "설계 결정(D1~D6)"을 더한 것이다. 둘이 다르면 이 파일을 따른다.

---

## 0. 맥락

- SK쉴더스 루키즈 최종 프로젝트, 보안컨설팅 트랙 「개인정보 처리 수탁사 점검 컨설팅」.
- 위탁사: 가상자산 거래소(가칭 SILO). 수탁사 A사: 비대면 본인확인 대행(이 저장소). 수탁사 B사: AI TM(범위 밖).
- 목적: 시스템을 만든 뒤 금융보안원 금융분야 취약점 분석·평가 기준(금취분평) + ISMS-P 기준으로 **설정 점검 수준**의 진단을 한다. 실제 공격·데이터 탈취는 하지 않는다. 설정만으로 판정할 수 없는 웹 항목은 가상 데이터와 테스트 계정으로 요청을 재현해 확인하는 데까지만 한다.
- 그래서 핵심 설계 원칙은 **"기본값은 양호(안전), 취약은 설정 플래그로 켠다"** 이다. 격리된 실습 환경 전용이다.
- 실제 개인정보는 절대 쓰지 않는다. 가상 인물 10명(Faker ko_KR, 고정 시드), 체크섬만 맞춘 가상 주민번호, 가짜 휴대폰번호만 쓴다.
- 개발 환경: macOS(Apple Silicon). 로컬에서 먼저 완성하고, AWS 배포는 다음 단계다.

## 1. 이번 1차 범위

포함: A사 Flask 앱 전체(위탁사 API, 인증창, 관리자 콘솔, 파기 배치), 모의 통신사 앱, 모의 진위확인(함수), 테스트 문자 수신함, 가짜 거래소 스크립트, 가상 인물 시드, 테스트.

제외: 실제 AWS 호출(인터페이스만 만들어 둠), Apache/서버 설정 스크립트, 거래소·B사 코드, OCR, 웹캠 촬영, 라이브니스, CSV 다운로드, 단계 재사용(중간 실패 시 처음부터).

## 2. 기술 스택

| 계층 | 선택 |
|---|---|
| 언어 | Python 3.11 |
| 웹 | Flask 3, Jinja2(autoescape), Bootstrap 5 CDN |
| 인증·폼 | Flask-Login(관리자), Flask-WTF(CSRF), pyotp(TOTP), bcrypt |
| 세션 | **Flask-Session 서버 사이드 세션**(cachelib 파일 또는 SQLAlchemy 백엔드). 기본 Flask 쿠키 세션은 서명만 되고 내용은 클라이언트가 읽을 수 있으므로 성명·휴대폰번호·CI를 절대 넣지 않는다 |
| DB | PostgreSQL 16(로컬은 docker compose), SQLAlchemy 2 + psycopg 3, Flask-Migrate |
| 암호화 | cryptography (AES-256-GCM), hmac/hashlib |
| HTTP 클라이언트 | requests |
| 테스트 | pytest |
| 운영 형태(나중) | Apache 2.4(mod_ssl, mod_proxy) → Gunicorn 127.0.0.1:8000 → Flask, RDS, S3, Rekognition, KMS, Secrets Manager |

교체 가능한 인터페이스로 만든다 (로컬 구현 / AWS 구현):
- `FaceMatcher`: `FakeFaceMatcher`(로컬) / `RekognitionFaceMatcher`(나중)
- `Storage`: `LocalStorage`(instance/uploads, UUID 파일명) / `S3Storage`(나중)
- `get_secret(name)`: 로컬은 `instance/dev_secrets.json` 또는 `.env` / 나중에 Secrets Manager

`FakeFaceMatcher` 규칙(로컬 테스트용): 기본 얼굴 1개·유사도 95. 파일명에 `noface` → 얼굴 0개, `twofaces` → 2개, `mismatch` → 유사도 40.

## 3. 폴더 구조

```
ekyc/
├─ app/
│  ├─ __init__.py          # create_app, Blueprint 등록, CSRFProtect(api는 exempt)
│  ├─ config.py            # 설정값, 취약 플래그(VULN_*)
│  ├─ models.py            # 13개 테이블
│  ├─ common/              # hmac_auth, ci, rrn, stage, crypto, secrets, log_mask, client_ip, storage, face
│  ├─ api/                 # IA-01, IA-12, 웹훅 전송(IA-11)
│  ├─ verify/              # IA-02~IA-10 (consent, phone, id, face, cancel, result)
│  ├─ test_inbox/          # IA-05 (실습 전용)
│  ├─ mock_mois/           # 함수만. HTTP 라우트 없음 (D3)
│  ├─ admin/               # 로그인, 이력, 상세, 이미지 열람, 접속기록, 권한
│  ├─ cli.py               # flask seed / create-client / create-admin / purge / expire
│  └─ templates/, static/
├─ carrier/                # 모의 통신사 별도 Flask 앱 + SQLite (MC-01, MC-02), 8443 자체 서명 TLS
├─ seed/make_people.py     # 고정 시드로 people.json 생성 (people.json은 gitignore)
├─ tools/fake_exchange.py  # 가짜 거래소: IA-01 호출, 웹훅 수신·서명 검증, IA-12 조회
├─ tests/
├─ docs/DECISIONS.md       # 명세에 없던 선택·변경 기록 (노션 반영용)
├─ docker-compose.yml, .env.example, .gitignore, README.md
```

## 4. 통합 인증 흐름 (16단계)

1. 거래소 → A사: 인증 요청 1회 (IA-01, API Key + HMAC)
2. A사 → 거래소: verification_id, auth_url(토큰 1회용·10분), expires_at(건 전체 20분)
3. 이용자 → A사: 인증창 진입 (IA-02, 토큰 확인 즉시 서버 세션 쿠키로 바꾸고 토큰 없는 주소로 리다이렉트)
4. 이용자 → A사: 동의 4종 (IA-03)
5. 이용자 → A사: 성명·휴대폰번호 (IA-04) → A사 → 모의 통신사: 명의 대조 (MC-01) → 일치 시 6자리 인증번호를 테스트 수신함으로 발송
6. 이용자 → A사: 수신함에서 확인한 인증번호 (IA-06)
7. A사 → 모의 통신사: CI 발급 (MC-02) → CI 보관, 성명은 서버 세션에 보관, stage=ID_CARD
8. 이용자 → A사: 신분증 사진 (IA-07), 사진 영역 얼굴 1개 검출
9. 이용자 → A사: 주민번호·발급일자 (IA-08). 성명은 서버 세션 값으로 고정, 요청 본문의 성명은 무시
10. A사: 주민번호 체크섬·생년월일 형식 검사
11. A사: X-01 CI 대조 — 입력 주민번호로 ci_mock 계산 = 휴대폰 CI? 다르면 재시도 없이 X01 종결
12. A사: 모의 진위확인 (성명 + 주민번호 + 발급일자, 함수 호출)
13. 이용자 → A사: 셀카 (IA-09), 얼굴 1개 검출
14. A사: CompareFaces(로컬은 Fake), 유사도 90 이상이면 일치
15. A사 → 거래소: 결과 웹훅 1회 (IA-11, product="ONBOARDING", HMAC 서명) → 이용자는 return_url로
16. (웹훅 유실 시) 거래소 → A사: 결과 조회 (IA-12)

## 5. stage와 서버 검사

| stage | 들어가는 조건 | 허용 요청 |
|---|---|---|
| CONSENT | 인증창 진입 | 동의, 취소 |
| PHONE | 동의 4종 완료 | 명의 대조·인증번호 발송·재발송, 인증번호 확인, 취소 |
| ID_CARD | CI 수령 | 신분증 업로드, 취소 |
| ID_CONFIRM | 신분증 업로드 완료 | 신분증 정보 입력(체크섬 → CI 대조 → 진위확인), 취소 |
| FACE | 진위확인 통과 | 셀카 업로드, 취소 |
| DONE | 최종 판정 | 없음 (결과 화면만) |

- 모든 인증창 라우트는 `@require_stage(...)` 데코레이터로 서버에서 stage를 확인한다. 위반 시 403.
- 매 요청마다 건 만료(20분)를 확인하고, 지났으면 P03으로 종결하고 웹훅을 보낸다.
- 종결된 건은 다시 열지 않는다. 거래소가 새 IA-01로 처음부터 다시 한다.

## 6. API

### 6.1 서버 간 서명 규칙 (거래소와 공유)
- 요청 헤더: `X-Api-Key`, `X-Timestamp`(유닉스 초, 현재 시각 ±5분), `X-Signature`
- `X-Signature = hex(HMAC-SHA256(key=위탁사별 HMAC Secret, msg=X-Timestamp 문자열 바이트 + 원본 요청 본문 바이트))`, 구분자 없음, 소문자 hex. 본문 없는 GET은 빈 바이트.
- 비교는 `hmac.compare_digest`. API Key는 `sha256` 해시로만 저장·조회.
- `clients.allowed_ips`에 없는 IP면 거부.
- 웹훅(IA-11)도 A사가 같은 방식으로 서명한다 (`X-Timestamp`, `X-Signature`).
- 알려진 한계: 메서드·경로를 서명하지 않아 본문 없는 GET은 5분 안에 다른 경로로 재사용될 수 있다. 지금은 문서대로 두고 DECISIONS.md에 남긴다.
- 이 서명 방식(hex, 구분자 없음, 유닉스 초)은 거래소 담당과 맞춰야 하므로 DECISIONS.md 맨 위에 적는다.

### 6.2 위탁사·이용자 API

| ID | 메서드 | 경로 | 방향 | 요청 | 응답 |
|---|---|---|---|---|---|
| IA-01 | POST | /api/v1/verifications | 거래소 → A사 | client_user_ref, return_url | 201: verification_id, auth_url, expires_at. 같은 client_user_ref로 진행 중인 건이 있으면 기존 건 반환 |
| IA-02 | GET | /verify/start/{token} | 브라우저 | — | 토큰 해시 확인·1회 사용 처리(원자적 UPDATE) → 서버 세션 → /verify/consent |
| IA-03 | POST | /verify/consent | 브라우저 | collect, uid, carrier_terms, biometric, 약관 버전 | 휴대폰 정보 입력 화면 |
| IA-04 | POST | /verify/phone/otp | 브라우저 | 성명, 휴대폰번호 (재발송은 `resend=1`, 서버 세션 값 재사용) | 마스킹 번호, 만료 시각, 재발송 가능 시각. 불일치면 P01·남은 횟수 |
| IA-05 | POST | /test-inbox/latest | 브라우저 | 수신함 키 | 최근 유효 인증번호 (실습 전용, 허용 IP만, 진단 범위 제외) |
| IA-06 | POST | /verify/phone/confirm | 브라우저 | 인증번호 | 성공 시 MC-02 → 신분증 업로드 화면 |
| IA-07 | POST | /verify/id-card | 브라우저 | 신분증 이미지 (jpg/png, 5MB 이하) | 얼굴 검출 결과, 성명이 채워진 정보 입력 화면 |
| IA-08 | POST | /verify/id-confirm | 브라우저 | 주민번호, 발급일자 (성명은 보내도 무시) | 체크섬 → CI 대조 → 진위확인 결과 |
| IA-09 | POST | /verify/face | 브라우저 | 얼굴 이미지 | 최종 판정 → 결과 화면 → return_url |
| IA-10 | POST | /verify/cancel | 브라우저 | — | P04 종결 → return_url |
| IA-11 | POST | {거래소 callback_url} | A사 → 거래소 | 7장 참고 | 200 |
| IA-12 | GET | /api/v1/verifications/{id} | 거래소 → A사 | — | 웹훅과 같은 항목 + ci_purged_at (주민번호·이미지 없음). 양호: 다른 위탁사 건은 404 |
| (IA-13) | — | 함수 `mock_mois.verify(name, rrn, issue_date) -> bool` | A사 내부 | — | 라우트 없음 (D3) |

- 브라우저 폼은 CSRF 보호. api Blueprint는 CSRF exempt(서명으로 보호).
- 성명·휴대폰번호·인증번호·주민번호·CI는 URL에 넣지 않는다.
- 접속 IP는 `client_ip()` 헬퍼 하나로만 읽는다. `TRUST_PROXY=True`일 때만 `X-Real-IP`(Apache가 덮어쓴 값), 아니면 `remote_addr`.

### 6.3 모의 통신사 API (A사 → 모의 통신사)
- 별도 Flask 앱(carrier/), SQLite, 로컬 https://localhost:8443 (자체 서명 인증서를 스크립트로 생성).
- A사는 `requests(..., verify=<통신사 인증서 파일>)`로 그 인증서만 신뢰한다(인증서 고정).
- 인증: `X-Carrier-Client-Key` 헤더. 통신사는 키 해시를 carrier_client와 대조.

| ID | 메서드 | 경로 | 요청 | 응답 |
|---|---|---|---|---|
| MC-01 | POST | /carrier/v1/identity-matches | verification_id, name, phone_number | 200: matched, reason(D1), match_token(일치 시), expires_at(5분) |
| MC-02 | POST | /carrier/v1/ci-issuances | verification_id, match_token | ci (88자). 토큰은 verification_id에 묶이고 1회용 |

- 통신사 응답 없음·오류 → A사는 P05로 종결, HTTP 503.

## 7. 웹훅 (IA-11)

성공:
```json
{
  "product": "ONBOARDING",
  "verification_id": "uuid",
  "status": "SUCCEEDED",
  "reason_code": "OK",
  "stages": { "phone": "PASSED", "id_card": "PASSED", "face": "PASSED" },
  "name": "홍길동",
  "birth_date": "1990-01-01",
  "ci_mock": "(88자 Base64)",
  "verified_at": "2026-11-26T14:03:21+09:00"
}
```
실패(예: X01):
```json
{
  "product": "ONBOARDING",
  "verification_id": "uuid",
  "status": "FAILED",
  "reason_code": "X01",
  "stages": { "phone": "PASSED", "id_card": "FAILED", "face": "NOT_STARTED" },
  "verified_at": null
}
```
- 실패·취소·만료 웹훅에는 name·birth_date·ci_mock을 넣지 않는다. 휴대폰만 성공한 결과는 보내지 않는다.
- stages 값: PASSED / FAILED / NOT_STARTED.
- 판정 시 1회 전송(타임아웃 3초), 결과를 callbacks에 기록. 유실은 IA-12로 보완.
- 웹훅 200 또는 첫 IA-12 조회 시 `ci_first_delivered_at` 기록, phone_events에 CI_DELIVERED.

## 8. 핵심 계산

- `ci_mock = Base64(HMAC-SHA512(key=CI 공유키, msg=하이픈 없는 주민번호 13자리))` → 88자. A사(`ekyc/ci-key`)와 모의 통신사(`carrier/ci-key`)가 같은 값을 쓴다.
- 주민번호 체크섬: 앞 12자리에 가중치 2,3,4,5,6,7,8,9,2,3,4,5를 곱해 더하고, `(11 - 합 % 11) % 10`이 13번째 자리. 7번째 자리 1·2는 1900년대, 3·4는 2000년대. 생년월일 유효성도 검사.
- 주민번호 저장: AES-256-GCM(nonce + 암호문), 키 `ekyc/rrn-key`.
- 휴대폰번호: 원문 저장 금지. `phone_key = HMAC-SHA256(번호)`, 화면·이력은 마스킹(010-****-1234).
- 인증번호: `secrets` 모듈로 6자리 생성. 검증값은 `code_mac = HMAC`, 테스트 수신함용으로만 `inbox_ciphertext`(AES-GCM) 보관. 사용·만료 즉시 삭제.
- 대조 토큰: A사는 `match_token_enc`로만 보관, CI 발급·종결 시 NULL.
- 동시성: 인증창 토큰 사용, 인증번호 성공, 대조 토큰 사용은 원자적 UPDATE(조건부) 또는 `SELECT ... FOR UPDATE`로 성공 1회만.

## 9. 설정값

인증창 토큰 10분·1회 / 건 전체 20분 / 인증번호 3분 / 재발송 60초(이내면 429) / 명의 대조 3회 / 인증번호 3회 / 얼굴 단계(E01~E05) 시도 합산 3회 / 얼굴 유사도 90 / 업로드 jpg·png 5MB(확장자 + 매직바이트) / CI는 첫 수령 후 7일, 미수령 시 판정 후 30일 / 관리자 5회 실패 30분 잠금, 세션 30분.

## 10. 판정 사유 코드와 HTTP 응답

| 코드 | 의미 | 처리 |
|---|---|---|
| OK | 모든 단계 통과 | 성공 웹훅 |
| P01 | 명의 대조 불일치(성명·번호 구분 없음) | 재입력, 3회째 종결 |
| P02 | 인증번호 3회 불일치 | 종결 |
| P03 | 인증창 토큰 또는 건 전체(20분) 만료 | 종결 |
| P04 | 이용자 취소 | 종결 |
| P05 | 모의 통신사 응답 없음·오류 | 종결 |
| E01 | 신분증 이미지 오류(형식·용량·얼굴 미검출) | 재업로드(얼굴 단계 시도에 포함) |
| E02 | 주민번호 형식·체크섬 오류 | 재입력(시도에 포함) |
| X01 | CI 불일치(휴대폰 명의자 ≠ 신분증 명의자) | 재시도 없이 즉시 종결, access_logs CI_MISMATCH, 관리자 표시 |
| E03 | 진위확인 불일치 | 재입력(시도에 포함) |
| E04 | 얼굴 미검출 또는 2명 이상 | 재업로드(시도에 포함) |
| E05 | 얼굴 유사도 미달 | 재업로드(시도에 포함) |
| E06 | 얼굴 단계 시도 합산 3회 초과 | 종결(마지막 실패 코드는 이력에) |

HTTP: 400 형식 오류 / 401 API Key·서명·타임스탬프 / 403 현재 stage에서 허용 안 됨 / 404 없는 건(양호 기준에서는 다른 위탁사 건도) / 409 종결된 건, 대조 토큰 재사용 / 410 인증창 토큰 만료·재사용 / 429 재발송 60초 이내 / 503 통신사 오류(P05).

## 11. 데이터 모델 (A사 PostgreSQL, 13개)

| 구분 | 테이블 | 주요 컬럼 |
|---|---|---|
| 공통 | clients | id(uuid), name, api_key_hash, hmac_secret_ref, callback_url, allowed_ips, status |
| 공통 | verifications | id(uuid), client_id, client_user_ref, token_hash(UNIQUE), token_used_at, stage, status, reason_code, face_attempts, return_url, expires_at, created_at, completed_at |
| 공통 | consents | verification_id, type(collect/uid/carrier_terms/biometric), version, agreed_at, ip |
| 공통 | callbacks | verification_id, url, payload_hash, http_status, retry_count, sent_at |
| 공통 | admins | id, login_id, password_hash(bcrypt), otp_secret(암호화), role(admin/auditor), allowed_ips, failed_count, locked_until, last_login_at |
| 공통 | access_logs | id, actor(admin/client/system), actor_id, action, target_id, reason, ip, created_at |
| 휴대폰 | phone_verifications | verification_id(PK·FK), status(PENDING/PASSED/FAILED), match_attempts, otp_attempts, match_token_enc, ci(NULL 또는 88자), ci_first_delivered_at, ci_purged_at, completed_at |
| 휴대폰 | phone_otps | verification_id(PK·FK), phone_key, issue_no, issued_at, code_expires_at, code_mac, inbox_ciphertext |
| 휴대폰 | test_phones | phone_key, phone_mask, inbox_key_hash, next_issue_at |
| 휴대폰 | phone_events | id, verification_id, event_kind, result_code, occurred_at, name_mask, phone_mask |
| 얼굴 | id_documents | verification_id(PK·FK), name, rrn_enc, birth_date, issue_date, ci_matched, **mois_matched(D4)**, s3_key, deleted_at |
| 얼굴 | face_checks | verification_id, s3_key, face_count, similarity, matched, deleted_at |
| 얼굴 | mock_mois_registry | name, rrn_hash(HMAC, 키 `ekyc/mois-key`), issue_date, status(정상/분실) |

CHECK 제약:
- verifications.stage IN ('CONSENT','PHONE','ID_CARD','ID_CONFIRM','FACE','DONE')
- verifications.status IN ('PENDING','SUCCEEDED','FAILED','CANCELLED','EXPIRED')
- verifications.reason_code IN (10장 코드), 진행 중 NULL
- face_attempts BETWEEN 0 AND 3, match_attempts·otp_attempts BETWEEN 0 AND 3
- expires_at > created_at
- phone_events.event_kind IN ('IDENTITY_MATCH','OTP_ISSUED','OTP_REISSUED','OTP_VERIFIED','CI_ISSUED','CI_DELIVERED','CI_PURGED','FAILED'). 성명·번호 마스킹값은 IDENTITY_MATCH에서만.

access_logs.action: REQUEST_RECEIVED, RESULT_QUERIED, CALLBACK_SENT, CI_MISMATCH, HISTORY_VIEW, HISTORY_DOWNLOAD(사유 필수), IMAGE_VIEW(사유 필수), ROLE_CHANGE, PURGED. 앱 코드는 access_logs·phone_events를 INSERT만 한다(UPDATE/DELETE 없음).

### 모의 통신사 SQLite
- subscriber: subscriber_ref, phone_key(통신사 자체 키로 HMAC), name_mac, name_mask, rrn_ciphertext(AES-256-GCM), registered_at
- match_session: token_digest, subscriber_ref, verification_id, expires_at, used_at
- carrier_client: client_id, key_digest, status

## 12. 시크릿 이름 (로컬은 seed가 dev_secrets.json 생성)

- A사: `ekyc/db`, `ekyc/clients/{client_id}/hmac`, `ekyc/rrn-key`, `ekyc/mois-key`, `ekyc/ci-key`, `ekyc/phone/phone-hmac-key`, `ekyc/phone/otp-hmac-key`, `ekyc/phone/inbox-key`, `ekyc/phone/match-token-key`, `ekyc/phone/carrier-client-key`, `ekyc/flask-secret`
- 모의 통신사: `carrier/match-hmac-key`, `carrier/rrn-key`, `carrier/ci-key`(A사와 같은 값), `carrier/tls`

## 13. 설계 결정 (노션 통합 문서에서 바꾼 것)

- **D1 (명의 대조 실패 사유를 내부에만 둔다)**: MC-01이 내부용 `reason`(`NAME_MISMATCH` / `NOT_SUBSCRIBER`)을 돌려준다. A사는 **둘을 P01 한 가지 메시지·같은 HTTP 응답으로 합친다.** 내부 `reason`은 로그·증적용이고 이용자 응답에는 구분이 드러나지 않는다(가입 여부 열거 방지).
- **D2 (X-01 통과는 면제되지 않는다)**: 최종 판정(F-09)은 **어떤 설정에서도 항상** `id_documents.ci_matched IS TRUE`를 요구한다. 얼굴 단계 진입 요건을 느슨하게 하는 설정이 들어오더라도 이 조건만은 그대로 둔다. 요건 검사는 `app/common/decision.py` 한 곳에 모아 두 경로(인증창·서버 간 API)가 같은 함수를 쓴다.
- **D3 (공개 오라클 제거)**: 모의 진위확인은 HTTP 라우트 없이 앱 내부 함수 호출이다. 테스트 수신함은 `TEST_INBOX_ALLOWED_IPS`로 제한하고 진단 범위에서 제외한다.
- **D4**: `id_documents.mois_matched` 컬럼 추가 (W-09 증적·관리자 표시용).
- **D5 (오픈 리다이렉트 방지)**: IA-01의 return_url은 해당 client의 callback_url과 같은 origin만 허용.
- **D6**: 인증번호 재발송은 IA-04에 `resend=1`로 보내고 서버 세션의 성명·번호를 재사용한다. 명의 대조는 다시 하지 않는다.

명세에 없는 선택을 하면 `docs/DECISIONS.md`에 한 줄씩 기록한다.

## 14. 보안 기본값(양호)과 취약 플래그

### 기본으로 구현할 양호 통제
- W-01 SQL은 SQLAlchemy 바인딩만 / W-02 autoescape + CSP 헤더 / W-03 CSRF + SameSite=Lax
- W-04 업로드: 확장자 + 매직바이트, UUID 파일명, 웹 루트 밖 저장 / W-05 이미지 열람은 짧은 유효기간의 서명 URL 또는 관리자 전용 라우트
- W-06 관리자 ID/PW + TOTP, 5회 실패 30분 잠금, 관리자별 허용 IP / W-07 토큰 1회·10분, 진입 즉시 서버 세션 쿠키(Secure·HttpOnly·SameSite=Lax), 관리자 30분 타임아웃
- W-11 인증번호 3회·3분·재발송 60초 / W-12 신분증 단계 요청마다 CI 수령 완료 확인 / W-13 진위확인 전에 X-01 통과 확인, 불일치 즉시 종결
- W-15 통신사 통신은 TLS + 인증서 고정 / W-16 신분증 단계 성명은 서버 세션 값만 사용
- 로그 마스킹 필터: 성명·휴대폰번호·인증번호·주민번호 원문, CI, 대조 토큰, 인증창 토큰을 로그에 남기지 않는다.
- 이미지: 판정 즉시 Storage에서 삭제하고 s3_key NULL, deleted_at 기록.

### 취약 플래그

플래그 목록과 "켜면 무엇이 뚫리는가"는 **저장소에 두지 않는다.** `private/VULN_MATRIX.md`에 있다
(gitignore 대상). 진단 대상 시스템의 명세서에 정답을 적어 두면 진단이 성립하지 않기 때문이다.

구현 기준은 `app/config.py`의 `VULN_FLAGS`다. 규칙은 그대로다.

- **기본값은 전부 `False`.** 플래그는 요청 시점에 `current_app.config`에서 읽는다.
- 플래그마다 테스트를 한 쌍 만든다: "기본값에서는 막힌다" / "플래그를 켜면 뚫린다".
  **넘지 말아야 하는 선**도 함께 고정한다(플래그 하나가 다른 통제까지 무너뜨리지 않는지).
- 켜는 방법은 `.env`에 `VULN_XXX=true`. 코드는 고치지 않는다.
  웹서버(Apache) 설정 취약은 `ops/apply_vuln.sh` / `ops/revert_vuln.sh`로 전환한다.
- 하나라도 켜져 있으면 기동 로그에 경고가 찍힌다.

서버·AWS 설정 영역의 취약은 앱 코드 범위 밖이고, 대상 목록도 `private/`에 둔다.

## 15. 관리자 콘솔

- 로그인 → TOTP → 이력 목록 → 상세(휴대폰 / 신분증 / 얼굴 탭).
- 목록·상세는 성명·번호·주민번호 마스킹, CI 비표시, X01 건 별도 표시, 단계별 상태·사유 코드.
- 이미지 열람·이력 다운로드는 사유 입력 필수, access_logs 기록. 이미지가 이미 파기됐으면 "파기됨" 표시.
- 역할: admin(이력·이미지 열람·권한 변경), auditor(이력·접속기록 조회만). 권한 변경은 ROLE_CHANGE 기록.
- F-01 고객사 등록은 1차에서는 CLI(`flask create-client`)로 한다. API Key와 HMAC Secret은 생성 시 한 번만 출력.

## 16. CLI·도구

- `python seed/make_people.py`: 고정 시드로 가상 인물 10명 생성 → people.json (성명, 주민번호, 발급일자, 휴대폰번호, 수신함 키). 9번 인물은 진위확인 대장에서 status=분실(E03 테스트용).
- `flask seed`: dev 시크릿 생성, mock_mois_registry·test_phones 적재. `python -m carrier.seed`: 통신사 명부 적재. 같은 people.json을 써야 CI가 일치한다.
- `flask create-client --name --callback-url --allowed-ips`, `flask create-admin --login-id --role` (TOTP 등록 URI 출력)
- `flask purge`: CI 보관기한 파기(NULL + ci_purged_at + CI_PURGED + access_logs PURGED), 남은 이미지 파기. `flask expire`: 20분 지난 PENDING 건 P03 종결 + 웹훅.
- `tools/fake_exchange.py`: (1) IA-01 서명 요청 후 auth_url 출력 (2) :9000에서 웹훅 수신·서명 검증·출력 (3) IA-12 조회. 이 파일은 거래소 담당에게 서명 구현 예시로 그대로 넘긴다.

## 17. 구현 순서와 완료 기준

| 단계 | 만들 것 | 완료 기준 |
|---|---|---|
| 1 | seed/make_people.py, common: ci, rrn(체크섬), hmac_auth, crypto, log_mask | 같은 인물의 ci_mock 일치, 체크섬·서명·마스킹 단위 테스트 통과 |
| 2 | create_app, config, models 13개 + 마이그레이션, docker-compose(PostgreSQL 16), CLI seed·create-client | 로컬 DB에 테이블 생성, seed 적재 |
| 3 | fake_exchange.py, IA-01, IA-02, IA-03, `@require_stage`, 서버 사이드 세션 | 스크립트 요청 → auth_url → 동의까지 |
| 4 | carrier 앱(MC-01·02, TLS, 클라이언트 키), IA-04·05·06, phone_events | 가상 인물로 CI 수령, stage=ID_CARD |
| 5 | IA-07, IA-08 (체크섬 → X-01 → 진위확인), Storage·FaceMatcher 인터페이스 | 같은 인물 통과 / 다른 인물 섞으면 X01 / 9번 인물 E03 |
| 6 | IA-09, 최종 판정, IA-11 웹훅, IA-12, 결과 화면 | **가짜 거래소가 SUCCEEDED 웹훅 수신 = 성공 경로 완주** |
| 7 | 실패 경로 전부 (P01\~P05, E01\~E06, X01, 만료, 취소, 동시 제출) | 사유 코드별 웹훅·HTTP 응답 테스트 |
| 8 | 관리자 콘솔, access_logs, purge·expire | 조회·열람·파기가 로그에 남음 |
| 9 | 취약 플래그 + 플래그별 테스트 쌍 (목록은 `private/`) | 기본값 전부 양호, 켜면 해당 동작만 바뀜 |

## 18. 작업 규칙

- 단계마다 pytest를 돌리고 **로컬 git 커밋**한다. 원격 저장소 push는 하지 않는다.
- 단계가 끝나면 3~5줄로 보고: 만든 것, 수동 확인 방법.
- 2단계와 6단계가 끝나면 멈추고 확인을 기다린다. 나머지는 이어서 진행한다.
- 명세에 없는 사소한 선택은 묻지 말고 가장 단순한 쪽으로 정한 뒤 DECISIONS.md에 기록한다. 단, 거래소와 공유하는 계약(API 경로·필드, 서명 방식, 웹훅 형식)이나 DB 스키마를 바꾸는 선택은 먼저 묻는다.
- 실제 AWS API를 호출하지 않는다. 실제 개인정보를 만들거나 쓰지 않는다. 시크릿·people.json·인증서·업로드 파일은 커밋하지 않는다(.gitignore).
- 식별자는 영어, 주석·문서·화면 문구는 한국어.
