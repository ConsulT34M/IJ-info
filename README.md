# IJ-info
수탁사 : (주)인증정보평가

---

## 이 저장소가 무엇인지

**A사 = (주)인증정보평가**, 위탁사(가상자산 거래소)의 **비대면 본인확인을 대행하는 수탁사**다.
이 저장소는 그 시스템을 실제로 만들어 보고, 만든 시스템을 금융보안원 금융분야
취약점 분석·평가 기준 + ISMS-P로 **설정 점검 수준**의 진단을 하기 위한 실습용 구현이다.

인증 흐름은 **휴대폰 본인확인 → 얼굴인증(eKYC)** 두 단계다.

```
거래소 ──IA-01──▶ A사 ──MC-01/02──▶ 모의 통신사      (명의 대조 → CI 발급)
   ▲              │
   │              ├─ 이용자: 동의 → 성명·번호 → 인증번호 → 신분증 → 주민번호·발급일자 → 셀카
   │              │                                   │
   │              │                        X-01 CI 대조 + 모의 진위확인
   └──IA-11 웹훅──┘                                   │
      (IA-12 조회로 보완)                     얼굴 대조(유사도 90)
```

16단계 전체 흐름과 판정 사유 코드는 [CLAUDE.md](CLAUDE.md)에 있다.

> ### 실습 전용이다
> - **실제 개인정보를 입력하지 않는다.** 가상 인물 10명([samples/people.json](samples/people.json))만 쓴다.
>   성명은 Faker ko_KR, 주민번호는 **체크섬만 맞춘 가상 값**, 휴대폰번호는 가짜 번호다.
> - 샘플 이미지도 전부 **합성 이미지**다. 실제 사람의 사진이 아니다.
> - 실제 AWS·실제 통신사·실제 진위확인을 호출하지 않는다(인터페이스만 두고 로컬 구현으로 대체).
> - 격리된 환경에서만 띄운다. 모든 서버는 `127.0.0.1`에만 바인딩한다.

---

## 빠른 시작

### 준비 (macOS 기준)

```bash
# Python 3.11 (uv)
curl -LsSf https://astral.sh/uv/install.sh | sh     # uv가 없으면
uv python install 3.11
uv venv --python 3.11
uv pip install -r requirements.txt

# Docker Desktop을 띄워 둔다 (PostgreSQL 16 컨테이너용)
```

**Windows는 아래 [Windows에서 실행](#windows에서-실행) 절을 본다.** WSL2를 권장한다.

### 1) 초기화 (몇 번이고 다시 돌릴 수 있다)

```bash
cp .env.example .env
bash tools/demo_reset.sh
```

웹서버 인증서 생성 → 컨테이너 기동(Apache·Gunicorn·PostgreSQL) → DB 초기화 → 마이그레이션 →
시크릿·대장·수신함·자료실 적재 → 모의 통신사 인증서·명부 → 가짜 거래소 고객사 등록 →
관리자 2명(admin1 / auditor1) 생성 → 샘플 이미지까지 한 번에 한다.
**끝나면 <https://localhost:9443> 이 이미 떠 있다.**
API Key·HMAC Secret은 `instance/fake_exchange.env`, 관리자 비밀번호·TOTP 시크릿은
`instance/demo_admins.env`에 **권한 600으로** 저장된다(둘 다 커밋되지 않는다).

### 2) 터미널 3개

| 터미널 | 명령 | 띄우는 것 |
|---|---|---|
| ① 모의 통신사 | `.venv/bin/python -m carrier` | `https://localhost:8443` (자체 서명 TLS) |
| ② A사 앱 | (컨테이너가 이미 띄움) 또는 `FLASK_APP=app .venv/bin/flask run` | `https://localhost:9443` / `http://127.0.0.1:8000` |
| ③ 가짜 거래소 | `source instance/fake_exchange.env && .venv/bin/python tools/fake_exchange.py serve` | `http://127.0.0.1:9000/callback` (웹훅 수신) |

### 3) 인증 한 바퀴 돌려 보기

```bash
source instance/fake_exchange.env
.venv/bin/python tools/fake_exchange.py request --client-user-ref demo-1
# 출력된 auth_url 을 브라우저에서 연다 (10분·1회용)
```

1. 동의 4종 체크 → 성명·휴대폰번호 입력 (가상 인물 값은 아래 명령으로 본다)
2. 실습 환경이라 문자가 오지 않는다 → **수신함 화면**에서 받는다.
   <http://127.0.0.1:8000/test-inbox/> 을 새 탭으로 연다.

   「휴대폰 등록」에 **성명 · 휴대폰번호 · 생년월일**을 넣는다. 통신사에 명의를 확인한 뒤
   이 창이 그 번호의 수신함이 된다(실제 PASS 앱을 깔 때 하는 통신사 본인확인에 해당).
   그 뒤로는 **「문자 확인」 버튼 하나**면 된다 — 수신함 키를 옮겨 적을 일이 없다(D99).

   번호·성명·생년월일이 통신사 명부와 **전부** 맞아야 등록된다. 어느 항목이 틀렸는지는
   알려주지 않는다(가입 여부 열거 방지).

   <details><summary>터미널에서 받고 싶다면 — 모의 PASS 앱</summary>

   ```bash
   # 처음 한 번: 통신사에 명의를 확인받고 기기를 등록한다
   .venv/bin/python tools/pass_app.py register --phone 010... --name 홍길동 --birth 1990-01-01
   # 그 뒤로는 문자가 오면 화면에 뜬다
   .venv/bin/python tools/pass_app.py watch
   ```

   같은 엔드포인트·같은 명의 확인을 쓴다. 다른 점은 키를 두는 곳뿐이다 —
   CLI는 `instance/pass_device.json`(권한 600), 브라우저는 서버 세션.
   `seed/people.json`의 `inbox_key`를 직접 넣는 기존 방법도 된다(화면 아래 「수신함 키를 직접 입력」).
   </details>
3. 신분증 사진으로 `samples/images/id_card.png` 업로드 → 주민번호·발급일자 입력
4. 얼굴 사진으로 `samples/images/selfie.png` 업로드 → "본인확인이 완료됐다"

   > `samples/images/*`는 합성 이미지라 기본 `FaceMatcher`(`fake`)가 **파일명으로** 판정한다.
   > 실제 사진으로 대조를 보려면 `samples/faces/`에 얼굴이 있는 jpg·png를 두고
   > `FACE_MATCHER=local`로 띄운다(OpenCV로 실제 검출·대조한다). AWS에서는 `rekognition`이다.
5. 터미널 ③에 `status: SUCCEEDED` 웹훅이 서명 검증과 함께 찍힌다
6. **관리자 콘솔** <http://127.0.0.1:8000/admin/login> 에서 `admin1` + TOTP로 들어가 이력을 본다

가상 인물 값(화면에 입력할 성명·번호·주민번호·수신함 키)은 이렇게 본다. `1`을 사람 번호로 바꾼다.

```bash
.venv/bin/python -c "import json;p={x['person_no']:x for x in \
json.load(open('seed/people.json'))['people']}[1];\
print('성명',p['name'],'/ 번호',p['phone_number'],'/ 주민번호',p['rrn'],\
'/ 발급일자',p['issue_date'],'/ 수신함 키',p['inbox_key'])"
```

관리자 TOTP 코드:

```bash
source instance/demo_admins.env && .venv/bin/python -c "import os,pyotp;\
print('admin1  ', pyotp.TOTP(os.environ['ADMIN1_TOTP_SECRET']).now());\
print('auditor1', pyotp.TOTP(os.environ['AUDITOR1_TOTP_SECRET']).now())"
```

건 하나를 마스킹된 상태로 들여다보기:

```bash
.venv/bin/python tools/peek.py --latest
```

---

## Windows에서 실행

**WSL2(Ubuntu)를 권장한다.** `tools/demo_reset.sh`가 bash 스크립트이고, 시크릿 파일 권한을
`chmod 600`으로 보호하는 등 경로·권한 처리가 리눅스 기준이다. WSL2 안에서는 macOS와 똑같은
명령이 그대로 동작한다. WSL 없이 쓰는 방법도 아래 B에 적었지만 제약이 있다.

### A. WSL2 + Ubuntu (권장)

**1) WSL2 설치** — PowerShell을 **관리자로** 열고:

```powershell
wsl --install -d Ubuntu
```

재부팅하면 Ubuntu 창이 떠서 사용자 이름·비밀번호를 만든다. 버전 확인:

```powershell
wsl -l -v        # VERSION 이 2 여야 한다. 1이면  wsl --set-version Ubuntu 2
```

> Windows 10은 2004(빌드 19041) 이상이어야 한다. 이미 WSL1 배포판이 있으면 위 명령으로 2로 올린다.

**2) Docker Desktop for Windows 설치**

- Settings → **General** → `Use the WSL 2 based engine` 체크
- Settings → **Resources → WSL integration** → `Ubuntu` 토글 **ON**
- Ubuntu 셸에서 `docker info` 가 나오면 성공이다(`docker: command not found` 면 위 토글이 꺼져 있다)

**3) 저장소는 반드시 WSL 안(`~/`)에 클론한다**

```bash
sudo apt update && sudo apt install -y git curl
cd ~
git clone https://github.com/ConsulT34M/IJ-info.git
cd IJ-info
```

> ### `/mnt/c/...`(윈도우 드라이브)에 두지 않는다
> - NTFS에는 `chmod 600`이 실제로 적용되지 않는다 → **시크릿·TOTP 시크릿·가상 인물 파일이
>   권한 보호 없이 놓인다.** 이 저장소는 그 권한에 기대고 있다.
> - 디스크 I/O가 몇 배 느려서 `pytest`·`demo_reset.sh`가 체감되게 느려진다.
> - 윈도우 탐색기에서 WSL 파일을 보려면 주소창에 `\\wsl$\Ubuntu\home\<사용자>\IJ-info` 를 넣는다.

**4) 이후는 macOS와 동일하다**

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.bashrc                       # 또는 셸을 다시 열기
uv python install 3.11
uv venv --python 3.11
uv pip install -r requirements.txt
cp .env.example .env
bash tools/demo_reset.sh
```

**5) 터미널 3개** — Windows Terminal에서 Ubuntu 탭을 3개 열고 위
[터미널 3개](#2-터미널-3개) 표의 명령을 그대로 쓴다.

**6) 브라우저** — Windows 쪽 Chrome/Edge에서 `http://127.0.0.1:8000`(개발 형태) 또는
`https://localhost:9443`(운영 형태, 진단 대상)을 그대로 열면 된다 (WSL2가 localhost를 포워딩한다).
운영 형태를 쓰려면 Docker Desktop의 **WSL2 통합**을 켜 둬야 한다. 열리지 않으면:

```bash
# WSL 안에서 접근되는지 먼저 확인
curl http://127.0.0.1:8000/healthz
```

- WSL 안에서는 되는데 윈도우에서 안 되면 `wsl --shutdown` 후 다시 띄운다.
- 그래도 안 되면 `FLASK_RUN_HOST=0.0.0.0 .venv/bin/flask run` 으로 띄우고
  `hostname -I` 로 나온 WSL IP로 접속한다. WSL2는 NAT 뒤에 있어 그 주소는 이 PC에서만
  닿지만, **실습이 끝나면 `127.0.0.1`로 되돌린다.**
- 모의 통신사(8443)는 A사 앱이 WSL 안에서만 호출하므로 브라우저에서 열 필요가 없다.

**7) 편집기** — VS Code + **WSL 확장**을 깔고 프로젝트 폴더에서 `code .` 를 하면
윈도우 VS Code가 WSL 안의 파일을 직접 편집한다(파일을 윈도우로 복사하지 않는다).

### B. WSL 없이 Windows에서 직접 (제약 있음)

앱 실행·pytest·모의 통신사·가짜 거래소는 PowerShell에서도 동작한다. 다만:

| 항목 | 상태 |
|---|---|
| `tools/demo_reset.sh` | **PowerShell에서 실행 안 된다.** Git Bash에서는 대체로 돌아가지만 검증하지 않았다 → 아래 수동 절차를 쓴다 |
| `chmod 600` (시크릿 파일 권한) | NTFS에서는 의미 있게 적용되지 않는다. `instance\` 안의 시크릿·관리자 TOTP 시크릿이 **권한으로 보호되지 않는다** |
| 한글 출력 | 레거시 콘솔에서 깨질 수 있다. `$env:PYTHONUTF8 = "1"` 를 먼저 설정하거나 Windows Terminal을 쓴다 |

준비:

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"   # uv 설치
uv python install 3.11
uv venv --python 3.11
uv pip install -r requirements.txt
Copy-Item .env.example .env
$env:PYTHONUTF8 = "1"
$env:FLASK_APP = "app"
```

초기화 — `demo_reset.sh`와 같은 순서를 손으로 한다:

```powershell
docker compose up -d

# (다시 초기화할 때만) A사 DB 비우기
docker compose exec -T db psql -U ekyc -d ekyc -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"

# 팀 공용 가상 인물 10명을 작업 위치로 복사
Copy-Item samples\people.json seed\people.json

.venv\Scripts\flask.exe db upgrade
.venv\Scripts\flask.exe seed

.venv\Scripts\python.exe -m carrier.make_certs
.venv\Scripts\python.exe -m carrier.seed

# 아래 두 명령이 출력하는 API Key·HMAC Secret·TOTP URI는 한 번만 보여준다. 바로 보관한다
.venv\Scripts\flask.exe create-client --name "KRX 가상화폐 거래소" `
  --callback-url http://127.0.0.1:9000/callback --allowed-ips 127.0.0.1
.venv\Scripts\flask.exe create-admin --login-id admin1  --role admin   --allowed-ips 127.0.0.1
.venv\Scripts\flask.exe create-admin --login-id auditor1 --role auditor --allowed-ips 127.0.0.1

.venv\Scripts\python.exe tools\make_sample_images.py --extras
```

터미널 3개(PowerShell 창 3개):

```powershell
# ① 모의 통신사
.venv\Scripts\python.exe -m carrier

# ② A사 앱
$env:FLASK_APP = "app"; .venv\Scripts\flask.exe run

# ③ 가짜 거래소 (위 create-client 출력값을 넣는다)
$env:EKYC_API_KEY = "..."; $env:EKYC_HMAC_SECRET = "..."
.venv\Scripts\python.exe tools\fake_exchange.py serve
```

자주 쓰는 것:

```powershell
# 가상 인물 값 (1을 사람 번호로 바꾼다)
.venv\Scripts\python.exe -c "import json;p={x['person_no']:x for x in json.load(open('seed/people.json',encoding='utf-8'))['people']}[1];print(p['name'],p['phone_number'],p['rrn'],p['issue_date'],p['inbox_key'])"

# 관리자 TOTP 코드 (create-admin이 출력한 otpauth URI의 secret= 값)
.venv\Scripts\python.exe -c "import pyotp;print(pyotp.TOTP('<시크릿>').now())"

# 건 하나 들여다보기
.venv\Scripts\python.exe tools\peek.py --latest

# 테스트
.venv\Scripts\python.exe -m pytest -q
```

### Windows에서 자주 걸리는 것

| 증상 | 원인·해결 |
|---|---|
| `bash: $'\r': command not found` | 스크립트가 CRLF로 받아졌다. `.gitattributes`가 막아 주지만, 이미 그렇게 받았다면 `git config --global core.autocrlf input` 후 다시 클론하거나 `sed -i 's/\r$//' tools/demo_reset.sh` |
| WSL에서 `docker: command not found` | Docker Desktop → Resources → WSL integration에서 Ubuntu 토글이 꺼져 있다 |
| `demo_reset.sh`가 "docker 데몬이 꺼져 있다"로 멈춘다 | Docker Desktop을 먼저 띄운다(트레이 아이콘이 초록색) |
| 포트 8000이 사용 중 | 다른 프로그램이 쓰고 있다. `netstat -ano \| findstr :8000` 으로 PID를 찾는다 |
| 포트 5432가 사용 중 | 윈도우에 PostgreSQL이 따로 설치돼 있다. 그 서비스를 멈추거나 `docker-compose.yml`의 포트를 `127.0.0.1:55432:5432`로 바꾸고 `.env`의 `EKYC_SECRET_EKYC_DB`로 접속 주소를 맞춘다 |
| 한글이 `?`나 깨진 글자로 보인다 | `$env:PYTHONUTF8 = "1"` 설정 후 다시 실행. Windows Terminal 사용 권장 |
| `flask: 명령을 찾을 수 없음` | 가상환경 경로가 리눅스와 다르다. Windows는 `.venv\Scripts\flask.exe`(리눅스·macOS는 `.venv/bin/flask`) |
| 첫 `flask run`에서 방화벽 창이 뜬다 | `127.0.0.1`에만 바인딩하므로 **허용하지 않아도 된다**. 취소해도 로컬 접속은 된다 |
| 파일 저장이 느리고 `pytest`가 오래 걸린다 | 저장소가 `/mnt/c/...`에 있다. WSL 홈(`~/`)으로 옮긴다 |

---

## 운영 형태로 띄우기 (Apache → Gunicorn → Flask)

개발 중에는 `flask run` 하나로 충분하지만, **진단 대상으로 쓸 때는 compose 스택**을 쓴다.
노션 구성도의 EC2 구성을 그대로 줄여 놓은 것이라 웹서버·OS·DBMS 점검 항목이 함께 생긴다.

```
브라우저 ──9443/https──▶ web(Apache 2.4) ──8000──▶ app(Gunicorn+Flask) ──5432──▶ db(PostgreSQL 16)
```

```bash
./ops/make_web_certs.sh        # 로컬 TLS 인증서 (처음 한 번)
docker compose up -d --build
open https://localhost:9443    # 자체 서명이라 경고가 뜬다. 진행하면 된다.
```

| | 주소 | 비고 |
|---|---|---|
| 웹서버(https) | <https://localhost:9443> | 진단은 여기로 한다 |
| 웹서버(http) | <http://localhost:9080> | 양호 설정에서는 https로 301 |
| 앱·DB | — | **호스트로 열지 않는다.** web 컨테이너만 접근한다 |

- 모의 통신사는 호스트에서 따로 띄운다(`python -m carrier`). 컨테이너는
  `host.docker.internal:8443`으로 부른다.
- `instance/`를 호스트와 공유하므로 `tools/demo_reset.sh` 한 번이면 양쪽 다 선다.

### 웹서버 양호/취약 전환

```bash
./ops/apply_vuln.sh     # 의도된 취약 설정으로
./ops/revert_vuln.sh    # 양호 기준으로 되돌림
git diff ops/apache/active.conf   # 지금 어느 상태인지
```

| 점검 항목 | 양호 | 취약 |
|---|---|---|
| 디렉터리 목록 노출 | 403 | 200 (목록 그대로) |
| HSTS 헤더 | 있음 | 없음 |
| http 평문 접속 | 301 → https | 200 (평문 서비스) |
| 에러 화면에 버전·OS | 없음 | `Apache/2.4.71 (Unix) OpenSSL/3.5.9` |
| 숨김 파일 `.env` | 403 | 200 (내용 그대로) |
| TRACE 메서드 | 405 | 200 |
| Server 헤더 | `Apache` | `gunicorn` |

설정을 바꾼 뒤에는 **동작을 확인한다.** 설정 파일에 지시어가 있다고 먹는다는 보장이 없다(D95).

```bash
./ops/check_web.sh          # 양호 기준 9항목
./ops/check_web.sh --vuln   # 취약 기준 7항목
```

앱 코드 쪽 취약은 `VULN_*` 환경변수로 따로 켠다. 둘은 독립이다.

---

## 진단 대상 화면

아래가 전부 같은 앱이다. **진단은 운영 형태(`https://localhost:9443`, Apache 뒤)에서 한다.**
코드를 고치며 볼 때는 `flask run`(`http://127.0.0.1:8000`)이 편하다.

| 구분 | 주소 | 들어가는 방법 |
|---|---|---|
| **회사 홈페이지** (공개) | `/` | 바로 열린다 |
| 공지사항 | `/notices`, `/notices/<번호>` | 검색어(`?q=`)·페이지(`?page=`) 파라미터가 있다 |
| **자료실** | `/library`, `/library/download` | 공개 문서 목록·검색·내려받기. DB를 쓰는 검색이다 |
| 고객지원·문의 폼 | `/support` | CSRF 토큰이 있는 POST 폼 |
| 개인정보 처리방침 | `/privacy` | 구현된 보유기간·안전조치와 내용을 맞췄다 |
| 실습 안내 | `/demo` | 진단 대상 목록과 시작 방법. **상단 메뉴에는 넣지 않는다** — 진짜 회사 사이트처럼 보이게 하려는 것이라 주소로만 들어간다 |
| 인증창 | `/verify/…` | **직접 못 연다.** 위탁사의 IA-01 요청으로 받은 1회용 주소로만 (`tools/fake_exchange.py request`) |
| 관리자 콘솔 | `/admin/login` | `flask create-admin`으로 만든 계정 + TOTP. 대시보드 · 인증 이력 · 위탁사 · 문의 · 접속기록 · 관리자 |
| 서버 간 API | `/api/v1/…` | `X-Api-Key` + `X-Timestamp` + `X-Signature` |
| 테스트 문자 수신함 | `/test-inbox/` | 실습 전용. **진단 범위에서 제외**한다. `tools/pass_app.py`(모의 PASS 앱)가 기기 등록으로 수신함 키를 받는다 |

회사 홈페이지는 **공개 노출면**이다. 공지·FAQ는 `app/site/content.py`의 고정 데이터이고(D83),
자료실과 문의는 전용 표 두 개(`site_documents`·`site_inquiries`)를 쓴다(D90). 문의는 담당자
연락처 수준만 받으며 **개인정보 흐름에는 들어가지 않는다.** 회사·대표자·주소·연락처는 **전부 가상**이고,
모든 화면 최상단에 그 사실을 띄운다.

---

## 시나리오별 확인표

성공 경로, 실패 코드 14종(P01\~P05 · E01\~E06 · X01), 관리자 콘솔, 파기 배치까지
**"어디를 누르면 무엇이 보여야 정상인지"** 를 표로 정리했다.

### ▶ [docs/DEMO.md](docs/DEMO.md)

---

## 위탁사(거래소) 연동 가이드

`tools/fake_exchange.py`가 **참고 구현**이다. A사 코드를 import하지 않고 표준 라이브러리 +
`requests`만 쓴다. 그대로 가져가도 된다.

연동 방식은 **두 가지**이고, IA-01의 `mode`로 고른다. 기본은 ⒜라서 **기존 연동은 고칠 것이 없다.**

### ⒜ 인증 화면을 A사가 띄운다 — `mode: "REDIRECT"` (기본)

거래소가 구현할 것은 **3개**다.

| ID | 방향 | 메서드·경로 | 용도 |
|---|---|---|---|
| **IA-01** | 거래소 → A사 | `POST /api/v1/verifications` | 인증 요청, `auth_url` 수신 |
| **IA-11** | A사 → 거래소 | `POST {callback_url}` | 결과 웹훅(판정 시 1회) |
| **IA-12** | 거래소 → A사 | `GET /api/v1/verifications/{id}` | 웹훅 유실 시 결과 조회 |

이용자를 `auth_url`로 보내면 동의·휴대폰·신분증·얼굴을 **A사 화면**이 받는다.
거래소는 주민등록번호와 신분증·얼굴 사진을 **아예 보지 않는다.**

### ⒝ 인증 화면을 거래소가 만든다 — `mode: "DIRECT"`

거래소가 자기 화면에서 입력을 받아 서버 간 API로 넘긴다. 화면만 거래소 것이고,
**휴대폰 본인확인·CI 발급·신분증·얼굴 판정은 전부 A사가 한다**(D98).

| ID | 방향 | 메서드·경로 | 용도 |
|---|---|---|---|
| **IA-01** | 거래소 → A사 | `POST /api/v1/verifications` (`mode: "DIRECT"`) | `auth_url` 없이 `verification_id`만 |
| **IA-23** | 거래소 → A사 | `POST /api/v1/verifications/{id}/phone/otp` | 명의 대조(MC-01) 후 인증번호 발송 |
| **IA-24** | 거래소 → A사 | `POST /api/v1/verifications/{id}/phone/confirm` | 인증번호 확인 → CI 수령(MC-02) |
| **IA-21** | 거래소 → A사 | `POST /api/v1/verifications/{id}/id-card` | 신분증 이미지 + 성명·주민번호·발급일자 |
| **IA-22** | 거래소 → A사 | `POST /api/v1/verifications/{id}/face` | 얼굴 이미지 → **최종 판정** |
| **IA-11 / IA-12** | | 위와 동일 | 결과 웹훅·조회(동기 응답으로도 받는다) |

- **거래소는 CI를 만들지도 보지도 않는다.** IA-21에 `ci`를 보내면 **400**이다.
  CI는 통신사가 발급해 A사 안에만 남는다.
  전처럼 거래소가 같은 키로 주민등록번호에서 CI를 계산해 보내면, X-01 대조가
  **같은 값을 두 번 계산해 비교하는 항등식**이 되어 검사 구실을 못 한다.
- **인증번호도 거래소로 가지 않는다.** IA-23 응답에는 마스킹된 번호와 만료 시각만 있다.
  이용자는 본인 휴대폰(<http://127.0.0.1:8000/test-inbox/>)에서 읽는다.
- 이미지는 **JSON 본문에 base64**로 담는다. 아래 서명 규칙을 그대로 쓸 수 있어서다.
  원본 5MB 상한은 그대로다.
- 다시 제출하면 되는 실패(E01~E05)는 **400** + `reason_code`·`attempts_left`,
  판정이 확정되면(OK·X01·E06) **200** + 웹훅과 같은 결과 본문이다.
- 실제 구현 예시는 거래소 저장소(`identity-routes.js`·`signup-routes.js`)에 있고,
  계약이 맞물리는지는 [tools/e2e/rkx_contract.mjs](tools/e2e/README.md)로 확인한다.

> **카메라를 붙여 시연할 때는 `FACE_MATCHER=local`로 띄운다.**
> 기본값 `fake`는 이미지를 읽지 않고 **파일명으로** 판정하므로, 카메라 앞에 누가 있든
> 전부 통과한다. `local`은 OpenCV로 실제 검출·대조하고, 쓰려면
> `uv pip install -r requirements-optional.txt`가 필요하다. AWS에서는 `rekognition`이다.
- ⒝를 쓰면 **주민등록번호·신분증 사진을 거래소가 직접 수집**하게 된다. 동의 수집과
  안전조치 책임이 거래소로 옮겨가므로 개인정보 처리방침을 함께 손봐야 한다.

전체 계약은 [docs/DECISIONS.md](docs/DECISIONS.md) 0.4절에 있다.

### 서명 규칙 (양방향 동일)

```
X-Api-Key    발급받은 API Key
X-Timestamp  유닉스 초 문자열 (현재 시각 ±300초)
X-Signature  hex(HMAC-SHA256(key=HMAC Secret, msg=X-Timestamp 바이트 + 원본 본문 바이트))
```

- 구분자 없음, **소문자 hex**, 본문 없는 GET은 **빈 바이트**에 서명한다.
- HMAC 키는 **Secret 문자열의 UTF-8 바이트**를 그대로 쓴다(Base64 디코딩하지 않는다).
- 비교는 상수 시간 비교(`hmac.compare_digest`)로 한다.
- 웹훅도 A사가 같은 방식으로 서명해서 보낸다. 다만 웹훅 헤더는
  `X-Timestamp`·`X-Signature`·`Content-Type`만이고 `X-Api-Key`는 없다.
- **웹훅은 받은 본문 바이트 그대로 검증한다.** JSON을 파싱해 다시 직렬화하면 서명이 깨진다.

구현이 맞는지 아래 기준값으로 확인한다.

| 입력 | 기대 서명 |
|---|---|
| `secret="test-secret"`, `ts="1700000000"`, `body={"client_user_ref":"u-1"}` | `8d15772196338b56f028ea824940d5cfa11c3716ec0d7cf57675a81d63d071a8` |
| 같은 키·시각, **본문 없음** | `1b74eaf87da46877ba651ac812b24a3bf01990e9ed0101b88268f60f965729e2` |

### IA-01 — 201과 200을 구분한다

```http
POST /api/v1/verifications
{"client_user_ref": "user-0001", "return_url": "https://exchange.example/done"}
```

```json
{
  "verification_id": "0e2f1c9a-…",
  "auth_url": "https://ekyc.example/verify/start/1795568659.A39MNCws…",
  "expires_at": "2026-11-26T14:20:00+09:00"
}
```

| 응답 | 의미 | 거래소가 할 일 |
|---|---|---|
| **201 Created** | 새 건을 만들었다 | `auth_url`로 이용자를 보낸다 |
| **200 OK** | 같은 `client_user_ref`로 **진행 중인 기존 건**을 돌려줬다. `verification_id`·`expires_at`은 그대로이고 **인증창 토큰만 새로 발급**된다(이전 토큰과 이미 열려 있던 인증창은 그 즉시 무효) | 똑같이 `auth_url`로 보낸다 |

- `auth_url`의 인증창 토큰은 **10분·1회용**이다. 두 번 열면 410이다.
- `return_url`은 **그 위탁사의 `callback_url`과 같은 origin**만 허용한다(오픈 리다이렉트 방지).
  운영(`EKYC_ENV=production`)에서는 `callback_url`·`return_url` 모두 **https만** 받는다.
- 건 전체 제한 시간은 **20분**이다.
- 그 외 응답: `400` 형식 오류 / `401` API Key·서명·타임스탬프 / `403` 허용 IP 아님.

### IA-11 — 결과 웹훅

성공:

```json
{
  "product": "ONBOARDING",
  "verification_id": "0e2f1c9a-…",
  "status": "SUCCEEDED",
  "reason_code": "OK",
  "stages": { "phone": "PASSED", "id_card": "PASSED", "face": "PASSED" },
  "name": "홍길동",
  "birth_date": "1990-01-01",
  "ci_mock": "(88자 Base64)",
  "verified_at": "2026-11-26T14:03:21+09:00"
}
```

실패(예: X01 — 휴대폰 명의자와 신분증 명의자가 다름):

```json
{
  "product": "ONBOARDING",
  "verification_id": "0e2f1c9a-…",
  "status": "FAILED",
  "reason_code": "X01",
  "stages": { "phone": "PASSED", "id_card": "FAILED", "face": "NOT_STARTED" },
  "verified_at": null
}
```

- **실패·취소·만료 웹훅에는 `name`·`birth_date`·`ci_mock`이 들어가지 않는다.**
- `status`: `SUCCEEDED` / `FAILED` / `CANCELLED` / `EXPIRED`,
  `stages` 값: `PASSED` / `FAILED` / `NOT_STARTED`.
- 판정 시 **1회만** 보낸다(타임아웃 3초). 재전송하지 않으므로 유실은 IA-12로 보완한다.
- 거래소는 **200**으로 응답한다. 200을 받은 시점이 CI 전달 시점으로 기록되고,
  그때부터 CI 보관기한 7일이 시작된다.

### IA-12 — 결과 조회

```http
GET /api/v1/verifications/{verification_id}      # 빈 본문에 서명
```

웹훅과 같은 항목에 `ci_purged_at`이 붙는다. **주민번호와 이미지는 어떤 경우에도 돌려주지 않는다.**
진행 중인 건도 조회할 수 있다(`status: "PENDING"`). 다른 위탁사의 건은 `404`다.

### 키 취급 원칙

> **API Key와 HMAC Secret을 git 저장소나 채팅으로 주고받지 않는다.**
> 두 값은 `flask create-client`가 **생성 시 한 번만** 출력한다. A사 DB에는 API Key의
> `sha256` 해시만 저장되고, HMAC Secret은 시크릿 저장소(로컬은 `instance/dev_secrets.json`,
> 운영은 AWS Secrets Manager)에만 들어간다. 분실하면 재발급한다.
> 전달은 비밀 관리 도구나 대면 등 별도 경로로 한다.

---

## 폴더 구조

```
.
├─ app/                     A사 Flask 앱
│  ├─ site/                 회사 홈페이지(공개 화면) — 소개·공지·고객지원·처리방침
│  ├─ api/                  IA-01, IA-12, 웹훅 전송(IA-11), IA-21·22(거래소 화면용 경로)
│  ├─ verify/               인증창 IA-02~IA-10, 건 종결
│  ├─ test_inbox/           IA-05 테스트 문자 수신함 (실습 전용, 진단 범위 제외)
│  ├─ mock_mois/            모의 진위확인 — 함수만, HTTP 라우트 없음
│  ├─ admin/                관리자 콘솔(로그인·이력·이미지 열람·접속기록·권한)
│  ├─ common/               서명·CI·주민번호·암복호화·마스킹·stage·저장소·얼굴 대조 등
│  ├─ config.py             9장 설정값 + 취약 플래그(VULN_*, 기본 전부 False)
│  ├─ models.py             13개 테이블 + 홈페이지 2개(자료실·문의)
│  └─ cli.py                flask seed / create-client / create-admin / purge / expire
├─ carrier/                 모의 통신사: 별도 Flask 앱 + SQLite + 자체 서명 TLS(8443)
├─ migrations/              Alembic 마이그레이션
├─ samples/                 팀원 공용 가상 데이터(인물 10명 + 합성 이미지 5개 + 자료실 공개 문서)
├─ seed/make_people.py      가상 인물 생성기(고정 시드)
├─ tools/                   demo_reset.sh · fake_exchange.py · pass_app.py · peek.py · make_sample_images.py
├─ tests/                   pytest (545개)
├─ docs/                    DEMO.md · DECISIONS.md · NOTION_SUMMARY.md
└─ docker-compose.yml       PostgreSQL 16 (127.0.0.1에만 바인딩)
```

커밋되지 않는 것: `.env`, `instance/` 전체(시크릿·세션·업로드 이미지·발급한 계정 정보),
`carrier/certs/`(TLS 개인키·인증서), `seed/people.json`(작업용 사본), 모든 `*.sqlite3`.
**각자 `tools/demo_reset.sh`로 자기 환경에서 만든다.**

---

## 테스트

```bash
# 기본: SQLite 메모리 — docker 없이도 돈다
.venv/bin/python -m pytest -q

# PostgreSQL로도 돌린다(별도 테스트 DB). 동시 제출 테스트가 함께 돈다
docker compose exec -T db psql -U ekyc -d postgres -c "CREATE DATABASE ekyc_test OWNER ekyc;"
TEST_DATABASE_URL=postgresql+psycopg://ekyc:ekyc@127.0.0.1:5432/ekyc_test \
  .venv/bin/python -m pytest -q
```

`@pytest.mark.postgres`가 붙은 동시 제출 테스트(인증창 토큰·인증번호·대조 토큰의 "성공 1회" 확인)는
실제 WSGI 서버를 띄워 8개 병렬 요청을 보낸다. SQLite로 돌리면 skip된다.

확인하는 층이 셋이다.

| 무엇 | 어떻게 | 무엇을 보나 |
|---|---|---|
| **A사 안쪽** | `pytest` | 16단계 흐름, 사유 코드별 응답, 플래그 쌍, 동시 제출 |
| **웹서버 설정** | `./ops/check_web.sh` (`--vuln`) | 지시어가 **실제로 먹는지** 요청을 보내 확인(D95) |
| **위탁사 연동** | `tools/e2e/rkx_contract.mjs` | 거래소가 쓰는 클라이언트 코드로 A사를 호출 |

### 위탁사(RKX) 연동 확인

거래소 서버 전체를 띄우지 않고도 **계약이 맞물리는지** 본다. RKX가 실제로 쓰는
`identity-service.js`의 `ijinfoRequest`를 그대로 불러 A사를 호출하므로, 서명 형식·엔드포인트·
본문 모양·사유 코드가 양쪽에서 어긋나면 여기서 잡힌다.

```bash
FACE_MATCHER=local .venv/bin/flask run --port 8000    # ① A사
.venv/bin/python -m carrier                            # ② 모의 통신사
git clone https://github.com/ConsulT34M/Rkx.git ../Rkx # ③ 거래소 코드

PYTHONPATH=. .venv/bin/python tools/e2e/reset_send_limits.py
source instance/fake_exchange.env
RKX_DIR=../Rkx PEOPLE_FILE=seed/people.json ID_CARD_IMAGE=samples/faces/id_card.png FACE_IMAGE=samples/faces/selfie.png NOFACE_IMAGE=samples/images/noface.png node tools/e2e/rkx_contract.mjs
```

시나리오 9개 32항목 — 성공 경로(**인증번호·CI가 응답에 새지 않는지** 포함), 위탁사 CI 거부,
X-01, P01 3회+사유 숨김, P02 3회+형식 오류 미차감, 재발송 429, E04 재제출, 휴대폰 단계
건너뛰기 차단, E03. 자세한 건 [tools/e2e/README.md](tools/e2e/README.md).

---

## 문서

| 문서 | 내용 |
|---|---|
| [CLAUDE.md](CLAUDE.md) | **기준 명세.** 16단계 흐름, stage 규칙, API, 데이터 모델 13개, 판정 사유 코드, 양호 통제와 취약 플래그 |
| [docs/DEMO.md](docs/DEMO.md) | 시연·확인 절차와 시나리오별 정상 결과표 |
| [docs/DECISIONS.md](docs/DECISIONS.md) | 설계 결정 기록(D1~D99). 맨 위 0절이 **거래소와 합의할 계약**(서명 규칙·응답 코드·웹훅 형식, 연동 방식 두 가지) |
| [docs/NOTION_SUMMARY.md](docs/NOTION_SUMMARY.md) | **노션 반영 요약.** 구현하면서 명세를 바꾼 결정만 노션 문서별(API 명세 / DB 설계 / 요구사항·기능 / 구성도)로 묶은 것 |
| [tools/e2e/README.md](tools/e2e/README.md) | **위탁사(RKX) 연동 확인.** 거래소가 실제로 쓰는 클라이언트 코드로 A사를 호출해 서명·엔드포인트·사유 코드를 맞춰 본다 |
| [samples/README.md](samples/README.md) | 샘플 데이터 설명(전부 가상) |
| [ops/apache/ekyc-good.conf](ops/apache/ekyc-good.conf) | 웹서버 **양호** 설정. 지시어마다 어떤 점검 항목인지 주석으로 적었다 |
| [ops/apache/ekyc-vuln.conf](ops/apache/ekyc-vuln.conf) | 웹서버 **의도된 취약** 설정. 양호본과 diff를 뜨면 차이가 바로 보인다 |

---

## 현재 상태

**1~9단계 완료. 기본값은 전부 "양호" 기준으로 동작한다.**

| 단계 | 내용 | 상태 |
|---|---|---|
| 1 | 가상 인물 시드, 공통 모듈(CI·주민번호·서명·암복호화·마스킹) | 완료 |
| 2 | `create_app`, 설정, 13개 테이블 + 마이그레이션, CLI | 완료 |
| 3 | IA-01·02·03·10, `@require_stage`, 서버 사이드 세션, 가짜 거래소 | 완료 |
| 4 | 모의 통신사(MC-01·02, TLS), IA-04·05·06, `phone_events` | 완료 |
| 5 | IA-07·08(체크섬 → X-01 → 진위확인), Storage·FaceMatcher | 완료 |
| 6 | IA-09 최종 판정, IA-11 웹훅, IA-12, 결과 화면 | 완료 |
| 7 | 실패 경로 전부(P01\~P05·E01\~E06·X01·만료·취소) + 동시 제출 | 완료 |
| 8 | 관리자 콘솔, `access_logs`, `purge`·`expire` | 완료 |
| 9 | 취약 플래그 6개(`VULN_W08`·`W09`·`W10`·`W14`·`W17`·`C10`) + 플래그별 테스트 쌍 | 완료 |
| + | 회사 홈페이지(공개 화면) — 진단용 공개 노출면 | 완료 |
| + | IA-21·22 — 위탁사가 화면을 만드는 서버 간 경로(`mode: DIRECT`) | 완료 |
| + | 자료실·문의 저장 + 웹 점검용 플래그 3개(`W01`·`W02`·`W05`) | 완료 |
| + | 운영 형태 스택 — Apache 2.4 → Gunicorn → Flask, 웹서버 양호/취약 전환 | 완료 |
| + | 얼굴 대조 실구현 — `local`(OpenCV) · `rekognition`(AWS). 파일명을 보지 않는다 | 완료 |
| + | 관리자 콘솔 대시보드 · 위탁사 목록 · 문의 답변 · 이력 필터 | 완료 |
| + | IA-23·24 — **휴대폰 본인확인도 A사가 한다**(DIRECT). CI는 A사 밖으로 나가지 않는다 | 완료 |
| + | 수신함 화면에서 휴대폰 등록 — 터미널 없이 인증번호를 받는다 | 완료 |

- 플래그는 **9개**다. 14장의 6개(`W08`·`W09`·`W10`·`W14`·`W17`·`C10`)에 더해,
  홈페이지 자료실·문의에서 웹 점검 항목을 재현하는 3개가 있다(D90):
  `VULN_W01`(SQL 인젝션) · `VULN_W02`(저장형 XSS) · `VULN_W05`(다운로드 경로 조작).
- **모든 `VULN_*` 플래그는 기본 `False`** 다. 플래그마다 "기본값에서는 막힌다 / 켜면 뚫린다"
  테스트 쌍이 있고(`tests/test_vuln_flags.py`), 넘지 말아야 하는 선도 함께 고정했다
  (예: `VULN_W09`를 켜도 X-01 CI 대조 통과는 항상 요구한다).
- 플래그를 켜는 방법은 `.env`에 `VULN_W08=true` 처럼 적는 것이다. 하나라도 켜져 있으면
  기동 로그에 `취약 플래그가 켜져 있다(실습 전용): …` 경고가 찍힌다.
  **진단 전에 이 줄로 상태를 확인한다.**
- **웹서버(Apache) 설정 취약**은 `ops/apply_vuln.sh` · `ops/revert_vuln.sh`로 전환한다(D91).
  디렉터리 목록·버전 노출·TRACE·HSTS·평문 접속 등 6가지가 한 번에 바뀐다.
- AWS 설정 영역의 취약(C-05 SSH 개방, C-12 로그 무결성, C-15·C-16 등)은 배포 단계에서 만든다.
- **진단 범위**: 설정 점검이 기본이고, 설정만으로 판정할 수 없는 웹 항목은
  **가상 데이터와 테스트 계정으로 요청을 재현해 확인하는 데까지만** 한다.
  실제 공격·데이터 탈취는 하지 않는다.
- 진단 대상 배포본은 `EKYC_ENV=production`으로 띄운다. 그때만 세션 쿠키 `Secure`,
  HSTS, https 강제가 켜진다.
