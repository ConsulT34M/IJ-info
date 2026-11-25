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

---

## 3단계 구현 세부

## D29. production은 https만 받는다

`EKYC_ENV=production`이면 `flask create-client`의 `callback_url`과 IA-01의 `return_url`은
**https만** 허용한다. dev는 로컬 테스트 때문에 http도 받는다. 판정은 `common/urls.allowed_schemes()`
한 곳에서만 한다. 결과 웹훅과 이용자 복귀가 평문으로 나가면 CI·판정 결과가 노출되기 때문이다.

## D30. `app/common/urls.py` 추가

`allowed_schemes()`(D29), `parse_absolute_url()`, `same_origin()`(D5)를 모았다. 스킴 정책과
오픈 리다이렉트 판정이 코드 여러 곳에 흩어지지 않게 한다.

## D31. 웹훅 전송 모듈(IA-11)을 3단계에 먼저 만들었다

명세 17장은 IA-11을 6단계로 두지만, 3단계에 이미 **만료(P03)·취소(P04) 종결**이 있어 그 시점에
결과 웹훅을 보내야 한다. `app/api/webhook.py`에 payload 생성(7장)과 서명 전송을 함께 넣고,
6단계에서 성공 payload와 IA-12가 같은 함수를 쓴다.

- 웹훅 헤더는 `X-Timestamp`, `X-Signature`, `Content-Type`만 보낸다(`X-Api-Key`는 보내지 않는다).
- 서명 대상 바이트는 `json.dumps(..., ensure_ascii=False, separators=(",", ":"))`의 결과다.
  거래소는 **받은 본문 바이트 그대로** 검증해야 한다(재직렬화하면 서명이 깨진다).
- 이미 `callbacks` 행이 있으면 다시 보내지 않는다(1회 전송).

## D32. `app/common/audit.py` 추가

`log_access()`, `log_phone_event()` INSERT 헬퍼. commit은 호출부에서 해서 같은 트랜잭션에 묶는다.

## D33. 허용 IP 아님은 403

API Key·서명·타임스탬프 실패는 401, `clients.allowed_ips`에 없는 IP는 **403**으로 구분한다.
10장 표에 없던 선택이다. 서버 간 통신이라 구분해도 공격자에게 주는 정보가 없고, 거래소 쪽 설정
오류를 빨리 찾을 수 있다.

## D34. 재진입은 현재 stage 화면으로 보낸다

IA-02는 명세대로 보통 `/verify/consent`로 보내지만, 진행 중인 건에 토큰을 재발급해 다시 들어온
경우에는 `stage_redirect()`가 **그 건의 현재 stage 화면**으로 보낸다. 중간 실패 시 단계를 재사용하는
것이 아니라(그건 명세 제외 항목), 종결되지 않은 건의 현재 위치로 돌아가는 것이다.

## D35. `auth_url`은 `PUBLIC_BASE_URL`로 만든다

IA-01은 거래소 서버가 호출하므로 요청의 Host 헤더를 믿을 수 없다. `PUBLIC_BASE_URL`
환경변수(기본 `http://127.0.0.1:8000`)로 `auth_url`을 만든다.

## D36. 인증창 토큰에 만료 시각을 담는다 (컬럼 추가 없음)

토큰 형식은 `{만료 유닉스초}.{임의값 43자}`이고 DB에는 **토큰 전체의 sha256**만 둔다.
만료 시각을 고치면 해시가 달라져 조회되지 않으므로, `token_issued_at` 컬럼 없이 10분 제한이 성립한다.
검사 순서: 형식 → 만료 → 조건부 원자적 UPDATE(`token_used_at IS NULL AND status='PENDING'`)로 1회 사용.
실패 사유(없는 토큰·사용된 토큰·만료)는 구분하지 않고 **모두 410**으로 답한다(오라클 제거).

## D37. pytest를 PostgreSQL로도 돌린다

`TEST_DATABASE_URL`이 있으면 그 DB로, 없으면 SQLite 메모리로 돌린다(기본). PostgreSQL로 돌릴 때는
세션 시작에 스키마를 한 번 만들고 테스트마다 `TRUNCATE ... RESTART IDENTITY CASCADE`로 비운다.
`@pytest.mark.postgres`를 붙인 테스트(7단계 동시 제출 등)는 SQLite에서는 skip된다.

```bash
.venv/bin/python -m pytest -q                                   # SQLite
TEST_DATABASE_URL=postgresql+psycopg://ekyc:ekyc@127.0.0.1:5432/ekyc_test \
  .venv/bin/python -m pytest -q                                 # PostgreSQL
```

## D38. 로컬 포트는 8000

맥 AirPlay 수신이 5000을 쓰므로 `FLASK_RUN_PORT=8000`으로 띄운다(운영 형태의 Gunicorn
127.0.0.1:8000과도 같다). `PUBLIC_BASE_URL`과 `tools/fake_exchange.py` 기본값도 8000이다.

## D39. 인증창 진입 때 세션을 새로 만들고, 종결 때 nonce를 지운다

IA-02에서 `session.clear()` 후 세션 ID를 재생성한다(세션 고정 방지). 종결(`terminate`) 시
`entry_nonce`를 NULL로 두어 열려 있던 탭이 더 쓰이지 못하게 한다(D7의 짝).

## D40. 약관 버전은 화면에 내보낸 값과 서버 값을 대조한다

동의 화면은 `Config.CONSENT_VERSIONS`를 hidden 필드로 내보내고, IA-03은 받은 값이 서버 값과
다르면 400으로 돌려보낸다(약관 갱신 중 제출된 동의를 기록하지 않기 위해). 기록에는 항상 서버 값을 쓴다.

---

## D41. `id_documents`는 IA-07에서 만든다 (5단계에 적용)

**IA-07(신분증 이미지 업로드) 시점에 `id_documents` 행을 만든다.**

- `name`은 서버 세션의 휴대폰 단계 성명으로 채우고 **NOT NULL을 유지**한다(W-16과 같은 값).
- `rrn_enc`·`birth_date`·`issue_date`만 NULL 허용으로 바꾼다. 대신 CHECK를 둔다:
  `ci_matched IS NULL OR (rrn_enc IS NOT NULL AND birth_date IS NOT NULL AND issue_date IS NOT NULL)`
  — X-01 대조까지 간 건이라면 세 값이 반드시 채워져 있다.
- 재업로드(E01)할 때는 `s3_key`를 새 파일로 바꾸고 **이전 파일은 즉시 Storage에서 삭제**한다.

**이유**: 업로드 직후 이탈·만료된 건의 이미지도 DB로 추적돼야 파기 배치(F-14, `flask purge`)가 지울 수
있다. 세션에만 들고 있으면 세션이 사라진 순간 그 파일은 어디에서도 참조되지 않는 고아 파일이 되고,
파기 배치가 찾을 수 없다. 그러면 `VULN_C10`("DB 참조만 지우고 Storage 객체는 남김")을 켠 상태와
기본(양호) 상태의 차이를 증적으로 보여줄 수 없다. 양호 기준에서 "DB 참조도 지우고 객체도 지운다"가
성립해야 플래그를 켠 쪽이 취약으로 드러난다.

## D42. 시크릿 `carrier/subscriber-key` 추가

명세 11장은 통신사 `subscriber.phone_key`를 "통신사 자체 키로 HMAC"이라고만 적었고 12장에 그 키 이름이
없었다. `carrier/subscriber-key`를 추가해 `phone_key`와 `name_mac`에 쓴다. A사의
`ekyc/phone/phone-hmac-key`와 다른 키이므로, A사의 phone_key로는 통신사 명부를 조회할 수 없다
(그래서 MC-01은 번호 원문을 받는다).

## D43. `app/common/carrier.py` 추가 (인증서 고정)

A사 → 모의 통신사 호출을 한 모듈에 모았다. `requests(..., verify=<통신사 인증서 파일>)`로
**그 인증서만** 신뢰한다(W-15). 전송 실패·비정상 응답은 `CarrierError`로 올리고 호출부가 P05로 종결한 뒤
503을 돌려준다.

## D44. 통신사 호출 타임아웃 5초

명세에 없던 값이다(`Config.CARRIER_TIMEOUT = 5`). 웹훅(3초)보다 길게 둔 것은 통신사 호출이
이용자 요청 처리 중간에 동기로 일어나기 때문이다.

## D45. P01 응답은 기본(양호)에서 200 + 같은 문구

명의 불일치와 미등록 번호를 구분하지 않고 "성명 또는 휴대폰번호가 일치하지 않는다. (남은 횟수 N회)"
한 문구로, **같은 HTTP 200**으로 다시 입력 화면을 보여준다(D1).
`VULN_W14`를 켜면 명의 불일치는 **400 + "입력한 성명이 명의자와 다르다"**,
미등록 번호는 **404 + "등록되지 않은 휴대폰번호다"**로 갈라진다. 이 차이가 W-14 진단 증적이다.

## D46. 인증번호 검증과 폐기를 하나의 조건부 UPDATE로 한다

```sql
UPDATE phone_otps SET code_mac = NULL, inbox_ciphertext = NULL
 WHERE verification_id = :id AND code_mac = :expected AND code_expires_at > :now
```
영향 행이 1이면 성공이다(8장의 "성공 1회만"). 비교가 DB에서 일어나 상수 시간은 아니지만,
MAC 값끼리의 비교라 원문·코드를 추측하는 데 쓸 수 없다. 성공과 동시에 검증값·수신함 암호문이 사라진다.

## D47. `app/common/phone.py` 추가

번호 정규화·성명 형식 검사·`phone_key`·인증번호 생성/MAC/수신함 암복호화·대조 토큰 암복호화를 모았다.
모든 값에 `verification_id`를 AAD나 MAC 입력으로 묶는다(D17).

## D48. 모의 통신사가 A사 공통 모듈을 재사용한다

통신사는 별도 앱·별도 DB·별도 키·별도 TLS를 쓰지만, `app.common`의 `crypto`·`ci`·`log_mask`·
`secrets`·`timeutil`은 import해서 쓴다. CI 계산식과 암호문 형식이 양쪽에서 갈라지면 X-01 대조가
조용히 깨지기 때문에, 공식은 한 곳에만 둔다.

## D49. 인증번호 만료·형식 오류는 시도 횟수에 넣지 않는다

`otp_attempts`는 **불일치**만 센다(P02는 "인증번호 3회 불일치"). 만료된 코드나 6자리가 아닌 입력은
400으로 돌려보내고 횟수를 올리지 않는다. 비교 자체를 하지 않으므로 무차별 시도에 쓸 수 없다.

## D50. MC-02 토큰 거부는 사유를 구분하지 않고 409

없는 토큰·이미 쓴 토큰·만료된 토큰·다른 `verification_id`의 토큰을 모두 **409**로 답한다.
어느 쪽인지 알려주면 토큰 상태를 묻는 오라클이 된다.

## D51. 세션을 비울 때 캐시된 CSRF 토큰도 버린다

`session.clear()`를 하면 CSRF 원본값도 사라지는데, 요청 컨텍스트(`g`)에 토큰이 캐시돼 있으면
다음 화면이 세션에 없는 토큰을 그대로 그려서 이어지는 POST가 실패한다.
`start_session()`·`end_session()`에서 `g`의 캐시도 함께 버린다.

## D52. 명부에 없는 번호도 발송 제한은 적용한다

`test_phones`에 없는 번호로 발송이 일어나면(명부에는 있지만 수신함 적재가 빠진 경우)
읽을 수 없는 `inbox_key_hash`로 행을 만들어 **번호 단위 60초 제한만** 걸고 경고 로그를 남긴다.
제한 레코드가 없다는 이유로 제한이 빠지지 않게 한다.
