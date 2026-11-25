# 설계 결정 기록

CLAUDE.md(기준 명세)에 없던 선택과 바꾼 것을 남긴다. 노션 반영용.
D1~D6은 CLAUDE.md 13장에 있다. 여기서는 D7부터 적는다.

---

## 0. 거래소와 맞춰야 하는 항목 (먼저 공유할 것)

이 절은 위탁사(가상자산 거래소 SILO) 담당과 **합의가 필요한 계약**이다. 바꾸면 양쪽을 같이 고친다.
구현 예시는 `tools/fake_exchange.py`를 그대로 넘긴다. 기준값(known answer)은 `tests/test_hmac_auth.py`에 있다.

### 0.1 서명 방식

```
X-Api-Key    위탁사 API Key (A사는 sha256 해시로만 보관)
X-Timestamp  유닉스 초 문자열 (예: "1700000000"), 현재 시각 ±300초
X-Signature  hex(HMAC-SHA256(key=HMAC Secret, msg=X-Timestamp 바이트 + 원본 요청 본문 바이트))
```

- 구분자 없음, **소문자 hex**(비교는 대소문자 무시), 본문 없는 GET은 빈 바이트.
- HMAC 키는 **Secret 문자열의 UTF-8 바이트**를 그대로 쓴다(Base64 디코딩하지 않는다).
- 비교는 `hmac.compare_digest`.
- 웹훅(IA-11)도 A사가 같은 방식으로 서명해서 보낸다.
- 기준값: `secret="test-secret"`, `ts="1700000000"`, `body={"client_user_ref":"u-1"}`
  → `8d15772196338b56f028ea824940d5cfa11c3716ec0d7cf57675a81d63d071a8`
  (빈 본문이면 `1b74eaf87da46877ba651ac812b24a3bf01990e9ed0101b88268f60f965729e2`)

알려진 한계(이번 범위에서는 문서로만 남긴다):
1. 메서드·경로를 서명하지 않아 본문 없는 GET 서명은 ±5분 안에 다른 경로로 재사용될 수 있다.
2. 타임스탬프와 본문 사이에 구분자가 없어 이론상 경계가 모호하다(타임스탬프가 항상 10자리 숫자라 실제 영향은 없다).

### 0.2 IA-01 응답 코드 (D12)

- **201 Created**: 새 건을 만들었다.
- **200 OK**: 같은 `client_user_ref`로 진행 중인 건이 있어 **기존 건을 돌려줬다**. 이때 `verification_id`와 `expires_at`(건 20분)은 그대로이고 `auth_url`의 **인증창 토큰만 새로 발급**된다. 이전 토큰과 이전에 열려 있던 인증창 세션은 그 시점에 무효가 된다(D7).
- 거래소는 두 코드를 모두 성공으로 보고 `auth_url`로 이용자를 보내면 된다.

### 0.3 웹훅 형식

CLAUDE.md 7장 그대로. 실패·취소·만료 웹훅에는 `name`·`birth_date`·`ci_mock`을 넣지 않는다.

---

## D7. 인증창 토큰 재발급 시 기존 인증창 세션 무효화

`verifications.entry_nonce`(문자열) 컬럼을 두고, IA-02에서 서버 세션에도 같은 값을 넣는다.
요청마다 세션의 nonce와 DB의 nonce를 비교해 다르면 **410**으로 막는다.
인증창 토큰을 새로 발급할 때(IA-01 재요청 등) nonce도 새로 만들므로, 그 건에 이미 열려 있던
브라우저 탭은 그 즉시 못 쓰게 된다. 1회용 토큰만으로는 "이미 입장한 탭"을 못 막아서 넣었다.

## D8. 진행 중 실패 코드는 `last_error_code`에 남긴다

`verifications.last_error_code`(NULL 허용, CHECK는 10장 코드 목록)를 추가한다.

- 중간 실패(P01, E01~E05)마다 `last_error_code`를 갱신한다. `reason_code`는 **종결 시에만** 기록한다
  (CHECK: 진행 중 `reason_code` NULL).
- E06으로 종결하면 `reason_code='E06'`, 마지막 실패 코드는 `last_error_code`에 남아 있다.
- 관리자 상세 화면에 `last_error_code`를 함께 보여준다.

## D9. 주민번호 성별 자리와 발급일자 검사 범위

- 7번째 자리는 **1·2(1900년대), 3·4(2000년대)만** 유효. 외국인(5~8)·1800년대(9·0)는 E02.
- 생년월일은 실제 달력 날짜여야 한다(90-02-30 거부).
- 발급일자는 `YYYY-MM-DD` 10자리 고정. 미래 날짜, 생년월일 이전도 **E02**로 묶고
  얼굴 단계 시도 합산(`face_attempts`)에 포함한다.
- 내부 error 값(FORMAT/CENTURY/BIRTH_DATE/CHECKSUM, FORMAT/FUTURE/BEFORE_BIRTH)은 로그·증적용이고
  이용자에게는 E02 한 가지 메시지만 보여준다(사유 노출 최소화).

## D10. 얼굴 단계 시도 합산의 경계

E01~E05 실패를 `face_attempts` 하나에 합산하고, **3번째 실패 응답이 곧 E06 종결**이다.
(값은 최대 3, CHECK `BETWEEN 0 AND 3` 유지. 10장의 "3회 초과"를 "3회 도달"로 읽는다.)
X01은 이 카운터와 무관하게 즉시 종결한다.

## D11. 인증번호 재발송 제한 (간격 + 횟수)

**간격**: `phone_otps.issued_at`(건 단위)과 `test_phones.next_issue_at`(번호 단위)을 **둘 다**
확인하고 하나라도 미래면 429. 발송 성공 시 `issued_at`을 갱신하고 `next_issue_at = now + 60초`로
둔다. 번호 단위 제한이 있어야 IA-01로 새 건을 만들어 60초 제한을 우회하는 걸 막는다.

**횟수**: 건당 발송은 **5회까지**(`phone_otps.issue_no` 기준, 최초 발송 포함).
초과하면 **429**로 거부하고 **건은 종결하지 않는다**(이용자는 취소하거나 20분 만료를 기다린다).
상한이 없으면 W-11(인증번호 발송 횟수 제한)이 취약으로 판정될 수 있어 넣었다.
설정값은 `Config.OTP_MAX_ISSUES = 5`.

## D12. IA-01 재요청 시 응답 → 0.2절 참고

진행 중(PENDING·미만료) 건이 있으면 `verification_id`·`expires_at`은 유지하고 인증창 토큰만
새로 발급해 **200**으로 돌려준다. A사는 `token_hash`만 보관하므로 원래 토큰 평문을 복원할 수 없고,
그 토큰은 1회용이라 이미 사용됐으면 재진입도 불가하기 때문이다.

## D13. 개발 환경 Python 3.11 (uv)

맥에 3.11이 없어 `uv python install 3.11` + `uv venv --python 3.11`로 맞췄다. 의존성은
`requirements.txt`에 핀으로 고정한다(진단 결과 재현용).

---

## 1단계 구현 세부

## D14. API Key / HMAC Secret 형식

둘 다 `secrets.token_urlsafe(32)` 문자열. API Key는 `sha256` hex로만 저장하고, HMAC Secret은
문자열의 UTF-8 바이트를 HMAC 키로 쓴다(0.1절). 생성 시 한 번만 출력한다.

## D15. `allowed_ips`가 비어 있으면 전부 거부

양호 기본값이다. 단일 IP와 CIDR(`10.0.0.0/24`)을 모두 받는다.
`flask create-client` / `flask create-admin`에서 허용 IP를 반드시 받는다.

## D16. 마스킹 규칙

- 성명: 홍길동 → `홍*동`, 김철 → `김*`, 남궁민수 → `남**수`, 1글자 → `*`
- 휴대폰: `010-****-1234` (앞 3자리 + 뒤 4자리만)
- 주민번호: `900101-1******` (뒤 6자리 가림. 생년월일은 판정 근거로 화면에 필요해 남긴다)
- 로그 필터는 ① 값 패턴(주민번호, 휴대폰, CI 88자 Base64) ② `key=value`/JSON 키
  (name, phone, code, otp, rrn, ci, token, match_token, inbox_key, password, api_key, secret 등)
  ③ 한국어 라벨(성명·이름·인증번호·휴대폰번호·주민번호)을 지운다.
  `client_name` 처럼 접미사로 붙은 키는 지우지 않는다.
- 라벨 없는 6자리 숫자(인증번호)는 식별자와 구분할 수 없어 필터에서 건드리지 않는다.
  **코드에서 애초에 인증번호를 로그에 넣지 않는 것이 1차 방어**이고, 필터는 2차 방어다.
- 포매팅이 깨진 로그 레코드는 필터에서 평평하게 만들어 핸들러에서 다시 터지지 않게 한다.

## D17. 암호문 형식과 AAD

AES-256-GCM, 저장 형식은 `nonce(12바이트) + 암호문·태그`. 키는 32바이트이고 `dev_secrets.json`에는
Base64 문자열로 둔다.

**AAD는 행 식별자로 묶는다.** `crypto.aad(table, column, row_id)`가 `테이블:컬럼:행 식별자` 바이트를
만들고, 모든 암복호화가 이 값을 쓴다. 다른 행의 암호문을 복사해 넣으면 복호화가 실패한다(행 치환 방지).

| 암호문 | 키 | AAD |
|---|---|---|
| `id_documents.rrn_enc` | `ekyc/rrn-key` | `id_documents:rrn_enc:{verification_id}` |
| `phone_verifications.match_token_enc` | `ekyc/phone/match-token-key` | `phone_verifications:match_token_enc:{verification_id}` |
| `phone_otps.inbox_ciphertext` | `ekyc/phone/inbox-key` | `phone_otps:inbox_ciphertext:{verification_id}` |
| `admins.otp_secret` | `ekyc/admin-otp-key` | `admins:otp_secret:{admin id}` |
| 통신사 `subscriber.rrn_ciphertext` | `carrier/rrn-key` | `subscriber:rrn_ciphertext:{subscriber_ref}` |

## D18. 시크릿 파일

`instance/dev_secrets.json`(권한 600, `instance/` 700). 경로는 `EKYC_SECRETS_FILE`로 바꿀 수 있고,
개별 값은 `EKYC_SECRET_<이름>`(대문자, `/`·`-`는 `_`) 환경변수가 파일보다 우선한다.
`carrier/tls`는 `{"cert": ..., "key": ...}` 두 경로를 담은 객체다.
`carrier/ci-key`는 `generate_dev_secrets()`가 항상 `ekyc/ci-key`와 같은 값으로 덮어쓴다.

## D19. 가상 인물 시드

고정 시드 `20261129`, 10명. 1900년대·2000년대 출생과 남녀가 모두 섞이도록 시드를 골랐다.
성별 자리에 맞춰 Faker의 `name_male`/`name_female`을 쓴다.
`person_no == 9`인 인물을 진위확인 대장에서 `분실`로 등록한다(E03 테스트용. 1부터 센 9번째).
발급일자는 만 17세 이후 ~ 어제 사이. `seed/people.json`은 커밋하지 않는다(권한 600).

---

## 2단계 구현 세부

## D20. 모델은 특정 DB에 묶지 않는다 (운영 PostgreSQL, 테스트 SQLite)

개발·운영은 PostgreSQL 16(docker compose)이고 마이그레이션도 PostgreSQL 기준이다.
다만 모델에는 PostgreSQL 전용 타입을 쓰지 않아서(`ARRAY` → `JSON`, UUID는 `sa.Uuid`)
테스트는 SQLite 메모리 DB에서 `create_all()`로 돌린다. docker 없이도 테스트가 돌아간다.
동시성 제어는 `SELECT ... FOR UPDATE` 대신 **조건부 원자적 UPDATE + rowcount 확인**을 기본으로
쓴다(두 DB에서 같이 동작하고, 8장 요구를 만족한다).

## D21. dev에서는 시크릿 파일을 자동 생성한다

`create_app()`이 `instance/dev_secrets.json`이 없으면 만든다. `EKYC_ENV=production`이면 만들지 않고
없으면 기동에 실패한다(시크릿은 Secrets Manager에서 와야 하므로).

## D22. 세션 쿠키 Secure는 환경에 따라 다르다

`EKYC_ENV=production`이면 `SESSION_COOKIE_SECURE=True`(+ HSTS 헤더, `WTF_CSRF_SSL_STRICT`),
로컬 dev는 http로 띄우기 때문에 False다. `SESSION_COOKIE_SECURE` 환경변수로 직접 켤 수도 있다.
HttpOnly·SameSite=Lax는 환경과 무관하게 항상 켠다. **진단 대상 배포본은 production으로 띄운다.**

## D23. 시각은 naive UTC로 저장하고 KST로 보여준다

DB 컬럼은 tz 없는 `DateTime`이고 값은 항상 UTC다(PostgreSQL·SQLite에서 같은 값이 나오게).
화면·웹훅·API 응답은 `timeutil.kst_isoformat()`으로 `+09:00` 문자열로 바꿔 내보낸다.

## D24. `app/common/timeutil.py` 추가

명세 3장의 common 목록에 없던 모듈이다. `now_utc()`, `to_kst()`, `kst_isoformat()`,
`seconds_left()`, `is_expired()`만 둔다. 만료 판정이 여러 곳에 흩어지지 않게 모았다.

## D25. 시크릿 `ekyc/admin-otp-key` 추가

12장 목록에 관리자 TOTP 시크릿을 암호화할 키가 없었다. 주민번호 키를 재사용하지 않고 별도 키를 둔다.

## D26. 대리 키(surrogate PK)를 쓴 테이블

명세 11장이 PK를 적지 않은 테이블에는 `id`(BigInteger, 자동증가)를 둔다:
`consents`, `callbacks`, `access_logs`, `phone_events`, `face_checks`, `mock_mois_registry`.

- `consents`: `UNIQUE(verification_id, type)` — 동의 종류별 1건
- `mock_mois_registry`: `UNIQUE(rrn_hash)` — 대장은 사람당 1건
- `face_checks`: 얼굴 시도마다 행을 남긴다(최대 3행)
- `phone_otps`·`phone_verifications`·`id_documents`는 명세대로 `verification_id`가 PK다

## D27. 명세에 없던 CHECK 제약 3개

- `verifications`: `(status='PENDING' AND reason_code IS NULL) OR (status<>'PENDING' AND reason_code IS NOT NULL)`
  — "진행 중 NULL"을 DB에서 강제한다(D8과 짝).
- `access_logs`: `HISTORY_DOWNLOAD`·`IMAGE_VIEW`는 `reason`이 비어 있으면 INSERT 불가(15장 요구).
- `phone_events`: `name_mask`·`phone_mask`는 `IDENTITY_MATCH`에서만 NULL이 아닐 수 있다(11장 요구).

## D28. 약관 버전은 `v1.0` 고정

`Config.CONSENT_VERSIONS`에 동의 4종의 버전을 둔다. 동의 기록(`consents.version`)에 그대로 들어간다.
