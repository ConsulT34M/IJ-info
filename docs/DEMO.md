# 시연 안내 (1~8단계)

격리된 실습 환경 전용이다. 가상 인물 10명과 가짜 번호·체크섬만 맞춘 가상 주민번호만 쓴다.

> **Windows 사용자**는 먼저 [README의 "Windows에서 실행"](../README.md#windows에서-실행)을 본다.
> 아래 명령의 `.venv/bin/...`은 macOS·WSL2 기준이고, WSL 없이 PowerShell에서 쓸 때는
> `.venv\Scripts\...`로 바꿔 읽는다.

---

## 1. 초기화

```bash
bash tools/demo_reset.sh          # 확인 후 진행 (-y 로 확인 생략)
```

끝나면 아래가 준비된다.

| 항목 | 위치 |
|---|---|
| A사 DB(13개 테이블) + 진위확인 대장 10명 + 테스트 수신함 10개 | PostgreSQL `ekyc` |
| 모의 통신사 가입자 10명 + 사업자 키 | `carrier/instance/carrier.sqlite3` |
| 가짜 거래소 API Key·HMAC Secret | `instance/fake_exchange.env` (600) |
| 관리자 2명(admin1 / auditor1) 비밀번호·TOTP 시크릿 | `instance/demo_admins.env` (600) |
| 샘플 이미지(커밋된 5개 + 형식 오류용 3개) | `samples/images/` |

관리자 OTP 코드는 이렇게 본다.

```bash
source instance/demo_admins.env && .venv/bin/python -c "import os,pyotp;\
print('admin1  ', pyotp.TOTP(os.environ['ADMIN1_TOTP_SECRET']).now());\
print('auditor1', pyotp.TOTP(os.environ['AUDITOR1_TOTP_SECRET']).now())"
```

가상 인물 정보(화면에 입력할 값)는 이렇게 본다. `1`을 사람 번호로 바꾼다.

```bash
.venv/bin/python -c "import json;p={x['person_no']:x for x in \
json.load(open('seed/people.json'))['people']}[1];\
print('성명',p['name'],'/ 번호',p['phone_number'],'/ 주민번호',p['rrn'],\
'/ 발급일자',p['issue_date'],'/ 수신함 키',p['inbox_key'])"
```

---

## 2. 터미널 3개

| 터미널 | 명령 | 띄우는 것 |
|---|---|---|
| ① 모의 통신사 | `.venv/bin/python -m carrier` | https://localhost:8443 (자체 서명 TLS) |
| ② A사 앱 | `FLASK_APP=app .venv/bin/flask run` | http://127.0.0.1:8000 |
| ③ 가짜 거래소 | `source instance/fake_exchange.env && .venv/bin/python tools/fake_exchange.py serve` | http://127.0.0.1:9000/callback (웹훅 수신) |

확인: ①은 `curl --cacert carrier/certs/carrier.crt https://localhost:8443/healthz`,
②는 `curl http://127.0.0.1:8000/healthz` → 둘 다 `{"status":"ok"}`.

인증을 시작할 때는 터미널 ④(아무 터미널)에서:

```bash
source instance/fake_exchange.env
.venv/bin/python tools/fake_exchange.py request --client-user-ref demo-1
# 출력된 auth_url 을 브라우저에서 연다 (10분·1회용)
```

**같은 `--client-user-ref`로 다시 요청하면 기존 건을 돌려주고(HTTP 200) 토큰만 새로 발급된다.**
새 건을 만들려면 `demo-2`, `demo-3`처럼 값을 바꾼다.

주요 화면:

| 화면 | 주소 |
|---|---|
| 회사 홈페이지 | <http://127.0.0.1:8000/> |
| 테스트 문자 수신함 | <http://127.0.0.1:8000/test-inbox/> |
| 관리자 콘솔 | <http://127.0.0.1:8000/admin/login> |

### 터미널 ⑤ — 모의 PASS 앱 (이용자의 휴대폰)

인증번호를 받는 자리다. `people.json`의 `inbox_key`를 복붙하는 대신, 통신사에 명의를
확인받고 수신함 키를 발급받는다(D85).

```bash
# 처음 한 번만. 번호·성명·생년월일이 통신사 명부와 전부 맞아야 한다
.venv/bin/python tools/pass_app.py register --phone 010... --name 홍길동 --birth 1990-01-01
# 새 문자를 기다린다 (Ctrl+C로 종료)
.venv/bin/python tools/pass_app.py watch
```

| 명령 | 하는 일 |
|---|---|
| `register` | 통신사 명의 확인(MC-03) → 수신함 키 발급 → `instance/pass_device.json` 저장 |
| `watch` | 새 인증번호가 오면 화면에 띄운다 |
| `inbox` | 지금 와 있는 인증번호 한 번 보기 |
| `status` | 등록 상태(키는 찍지 않는다) |
| `logout` | 저장된 키 삭제 |

**같은 번호로 다시 등록하면 이전 기기는 못 쓴다.** 기기 하나만 유효하다.

---

## 3. 시나리오별 "무엇이 보여야 정상인지"

> 휴대폰번호마다 **60초 재발송 제한**이 걸리므로 시나리오마다 **다른 사람 번호**를 쓴다.
> 아래 "사람" 열의 번호가 그 용도다.

### 3.1 성공 경로 (OK)

| 단계 | 조작 | 정상 결과 |
|---|---|---|
| 1 | 터미널 ④: `fake_exchange request --client-user-ref demo-ok` | HTTP 201, `auth_url` 출력 |
| 2 | 브라우저에서 `auth_url` 열기 | 동의 화면. 주소창에 토큰이 없다(`/verify/consent`) |
| 3 | 같은 `auth_url` 을 새 탭에서 다시 열기 | "이미 사용했거나 만료된 주소" (410) |
| 4 | 동의 4종 전부 체크 → 진행 | 휴대폰 정보 입력 화면 |
| 5 | 동의 1개만 빼고 진행 | 400 + "필수 동의 4종에 모두 동의해야" |
| 6 | 사람 1의 성명·번호 입력 | 인증번호 화면. **마스킹된 번호(010-\*\*\*\*-1234)만** 보이고 인증번호는 화면에 없다 |
| 7 | 터미널 ⑤ 모의 PASS 앱(`pass_app.py watch`) | 문자가 도착해 6자리 인증번호가 뜬다. 수신함에 `inbox_key`를 직접 넣어도 된다 |
| 8 | 인증번호 입력 | 신분증 사진 등록 화면 |
| 9 | `samples/images/id_card.png` 업로드 | 신분증 정보 입력 화면. **성명은 바꿀 수 없게 채워져 있다** |
| 10 | 사람 1의 주민번호·발급일자 입력 | 얼굴 사진 등록 화면 |
| 11 | `samples/images/selfie.png` 업로드 | "본인확인이 완료됐다" + 돌아가기 버튼 |
| 12 | 터미널 ③ 확인 | `서명 검증 성공` + `status: SUCCEEDED`, `name`·`birth_date`·`ci_mock`·`verified_at(+09:00)` |
| 13 | `tools/peek.py --latest` | CI "보관 중(88자, 비표시)", 이미지 2건 "파기됨", `phone_events` 5건 |
| 14 | `fake_exchange query <verification_id>` | 같은 결과 + `ci_purged_at: null` |

### 3.2 실패 경로

| 코드 | 사람 | 조작 | 정상 결과 |
|---|---|---|---|
| **P01** | 2 | 휴대폰 화면에서 **틀린 성명** + 맞는 번호로 3번 제출 | 1·2회는 같은 문구 1종("성명 또는 휴대폰번호가 일치하지 않는다. 남은 횟수 N회"), 3회째에 거래소로 돌아간다. 웹훅 `P01` |
| **P01(미등록)** | — | 아무 성명 + `01099998888` | **P01과 똑같은 문구·똑같은 응답**(미등록인지 알려주지 않는다) |
| **P02** | 3 | 인증번호를 3번 틀리게 입력 | 1·2회는 "남은 횟수 N회", 3회째에 거래소로 돌아간다. 웹훅 `P02` |
| **429(간격)** | 4 | 인증번호 화면에서 바로 "재발송" | 429 + "잠시 후 다시 요청한다(60초 제한)" |
| **429(횟수)** | 4 | 60초마다 재발송을 6번 | 6번째에 429 + "건당 5회까지". **건은 종결되지 않는다** |
| **E01** | 5 | 신분증으로 `noface.png` 업로드 | 400 + "얼굴이 하나만 보이도록" (남은 시도 2회) |
| **E01(형식)** | 5 | `not_an_image.png` 업로드 | 400 + "이미지 파일이 아니다" |
| **X01** | 6 | 사람 6으로 휴대폰 인증 후 **사람 7의 주민번호** 입력 | 재시도 없이 거래소로 돌아간다. 웹훅 `X01`, 관리자 목록에 **노란 줄 + "X01 명의 불일치"** |
| **E03** | 9 | 사람 9(진위확인 대장 `분실`)로 끝까지 진행 | 400 + "신분증 정보가 확인되지 않는다" (재입력 가능) |
| **E04** | 8 | 얼굴 사진으로 `noface.png` / `twofaces.png` | 400 + "얼굴이 하나만 보이는 사진으로" |
| **E05** | 8 | 얼굴 사진으로 `selfie_mismatch.png` | 400 + "신분증 사진과 일치하지 않는다" |
| **E06** | 10 | E01·E04·E05를 **합쳐서** 3번 | 3번째에 거래소로 돌아간다. 웹훅 `E06`, 관리자 상세의 `last_error_code`에 마지막 코드 |
| **P04** | 아무나 | 아무 화면에서 "취소하고 돌아가기" | 거래소 `return_url`로 이동. 웹훅 `P04` |
| **P05** | 아무나 | 터미널 ①(통신사)을 끄고 휴대폰 인증 시도 | 503 화면. 웹훅 `P05` |
| **P03** | 아무나 | 건을 만들고 20분 기다리거나 `flask expire` 실행 | `1건을 종결했다` + 웹훅 `P03`, 이후 그 인증창은 410 |

실패 웹훅에는 `name`·`birth_date`·`ci_mock`이 **없어야** 정상이다(터미널 ③에서 확인).

### 3.3 관리자 콘솔

| 조작 | 정상 결과 |
|---|---|
| <http://127.0.0.1:8000/admin/> 바로 열기 | 로그인 화면으로 보낸다 |
| admin1 + 비밀번호 | OTP 입력 화면(아직 콘솔은 안 열린다) |
| OTP 코드 입력 | 인증 이력 목록 |
| 비밀번호를 5번 틀리기 | 5번째에 "계정이 잠겼다" → 30분간 올바른 비밀번호도 거부 |
| 목록 보기 | 성명 `홍*동`, 번호 `010-****-1234`, 주민번호 `900101-1******`. **CI는 어디에도 없다**. 시각은 모두 `+09:00` |
| X01 건 | 줄이 노랗게, 사유에 `X01 명의 불일치` 배지 |
| 상세 → 휴대폰 탭 | 시도 횟수, CI "보관 중(비표시)" 또는 "파기됨", `phone_events` 전체 |
| 상세 → 신분증 탭 | 마스킹된 주민번호, X-01/진위확인 "통과·불일치", 이미지 "보관 중/파기됨" |
| 상세 → 얼굴 탭 | 시도별 얼굴 수·유사도·일치 여부 |
| 상세 → 웹훅 탭 | 전송 시각·HTTP 상태·본문 해시 |
| 이미지 열람 사유를 4자 이하로 | 다시 입력하라는 경고. **기록도 남지 않는다** |
| 사유를 5자 이상 적고 열람 | 이미지가 보이고, 접속기록에 `IMAGE_VIEW` + 사유가 남는다 |
| 이미지 주소를 사유 없이 직접 열기 | 403 |
| 열람 후 60초 지나 이미지 주소 새로고침 | 410 (사유를 다시 입력해야 한다) |
| 이미 파기된 건의 이미지 열람 | "파기됨" 안내, 기록도 남지 않는다 |
| 접속기록 화면 | `HISTORY_VIEW`·`IMAGE_VIEW`·`CI_MISMATCH`·`CALLBACK_SENT`·`PURGED` 등이 KST로 |
| auditor1로 로그인 | 이력·접속기록은 보이고, 관리자 메뉴는 없다. 이미지 열람은 403 |
| 관리자 메뉴에서 auditor1 → admin 변경 | 접속기록에 `ROLE_CHANGE` + `auditor → admin` |
| 자기 역할을 auditor로 변경 | 400 (자신의 권한은 낮출 수 없다) |

### 3.4 파기 배치

| 조작 | 정상 결과 |
|---|---|
| `FLASK_APP=app .venv/bin/flask purge --dry-run` | 대상 건수만 출력하고 아무것도 지우지 않는다 |
| `flask purge` | `CI n건, 이미지 참조 m건을 파기했다` |
| 파기 후 `tools/peek.py <id>` | CI "파기됨", 이미지 "파기됨", `phone_events`에 `CI_PURGED`, 접속기록에 `PURGED` |
| 파기 후 `fake_exchange query <id>` | `ci_mock`이 사라지고 `ci_purged_at`에 시각이 들어온다 |

보관기한은 **첫 수령 후 7일 / 미수령 시 판정 후 30일**이라 방금 만든 건은 대상이 아니다.
억지로 보고 싶으면 `phone_verifications.ci_first_delivered_at`을 8일 전으로 바꾼 뒤 돌린다.

---

## 4. 자주 걸리는 것

| 증상 | 원인·해결 |
|---|---|
| 인증번호 발송이 429 | 같은 번호를 60초 안에 다시 썼다. 다른 사람 번호를 쓰거나 1분 기다린다 |
| `auth_url`이 410 | 1회용이다. 다시 `fake_exchange request`를 돌린다 |
| 동의 화면이 403 | 그 건이 이미 다음 단계로 갔다. 새 `--client-user-ref`로 시작한다 |
| 수신함이 "유효한 인증번호가 없다" | 아직 발송하지 않았거나 3분이 지났다. 인증창에서 재발송한다 |
| PASS 앱이 "등록할 수 없다" | 번호·성명·생년월일 중 하나가 통신사 명부와 다르다. 셋 다 맞춰야 한다 |
| PASS 앱이 "수신함을 찾을 수 없다" | 그 번호로 다른 기기를 등록했거나 `flask seed`가 키를 되돌렸다. 다시 `register` 한다 |
| 통신사 호출이 503 | 터미널 ①이 꺼졌거나 `carrier/certs/carrier.crt`가 없다 |
| 관리자 화면이 403 | 그 계정의 허용 IP 밖이다(기본 127.0.0.1) |
| 포트 8000이 사용 중 | 맥 AirPlay 수신 또는 이전 `flask run`이 남아 있다. `lsof -nP -iTCP:8000 -sTCP:LISTEN` 으로 확인 |
