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

## D11. 인증번호 재발송 60초 제한의 기준점

`phone_otps.issued_at`(건 단위)과 `test_phones.next_issue_at`(번호 단위)을 **둘 다** 확인하고
하나라도 미래면 429. 발송 성공 시 `issued_at`을 갱신하고 `next_issue_at = now + 60초`로 둔다.
번호 단위 제한이 있어야 IA-01로 새 건을 만들어 60초 제한을 우회하는 걸 막는다.
재발송 **총 횟수 상한은 두지 않는다**(건 전체 20분 만료가 상한, `issue_no`로 기록만 남긴다).

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
Base64 문자열로 둔다. `crypto.encrypt/decrypt`는 AAD를 받을 수 있게 열어 두고, 어느 컬럼에 무엇을
묶을지는 2단계(모델)에서 정한다.

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
