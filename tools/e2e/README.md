# tools/e2e — 위탁사(RKX) ↔ A사(IJ-info) 연동 확인

클라우드에 올리기 전에 **두 회사 코드가 실제로 맞물리는지** 보는 자리다.
pytest는 A사 안쪽만 본다. 여기서는 **RKX가 실제로 쓰는 클라이언트 코드**
(`identity-service.js`의 `ijinfoRequest`)를 그대로 불러 A사를 호출한다.
서명 형식·엔드포인트·본문 모양·사유 코드가 양쪽에서 맞는지 확인한다.

RKX 서버 전체를 띄우려면 MySQL이 필요하다. 그게 없어도 연동 계약은 이 스크립트로 본다.

## 준비

```bash
# 1. A사 — 실제 얼굴 사진으로 대조하려면 local 을 쓴다
FACE_MATCHER=local flask run --port 8000

# 2. 모의 통신사
python -m carrier

# 3. 같은 people.json 으로 양쪽을 적재한다 (CI 가 맞아야 한다)
flask seed && python -m carrier.seed

# 4. RKX 저장소를 옆에 받아 둔다
git clone https://github.com/ConsulT34M/Rkx.git ../Rkx
```

`samples/faces/`에 실제 얼굴 사진(`id_card.png`, `selfie.png`)을 둔다. gitignore 대상이다.

## 실행

```bash
# 번호별 60초 발송 제한만 되감는다(통제를 끄는 게 아니다)
PYTHONPATH=. python tools/e2e/reset_send_limits.py

source instance/fake_exchange.env
RKX_DIR=../Rkx \
PEOPLE_FILE=seed/people.json \
ID_CARD_IMAGE=samples/faces/id_card.png \
FACE_IMAGE=samples/faces/selfie.png \
NOFACE_IMAGE=samples/images/noface.png \
node tools/e2e/rkx_contract.mjs
```

## 보는 것

| | 시나리오 |
|---|---|
| 1 | 성공 경로 — 인증번호가 **응답에 없고**, CI도 **응답에 없고**, 최종 SUCCEEDED |
| 2 | 위탁사가 `ci`를 보내면 400 |
| 3 | X-01 — 휴대폰은 A, 신분증은 B → 즉시 종결, 실패 결과에 CI·성명 없음 |
| 4 | P01 3회 종결, **미등록 번호와 이름 불일치가 같은 응답**(D1) |
| 5 | P02 3회 종결, 형식 오류는 횟수에 넣지 않음 |
| 6 | 재발송 60초 제한 429 |
| 7 | E04 재제출 → 올바른 사진으로 통과 |
| 8 | 휴대폰 단계를 건너뛸 수 없음 |
| 9 | E03 — 분실 신고된 신분증 |

E05(유사도 미달)는 **다른 사람의 실제 얼굴 사진**이 있어야 한다.
`FACE_MATCHER=local`은 파일명을 보지 않으므로 이름만 바꾼 같은 사진으로는 만들 수 없다.
그 경로는 `tests/test_api_direct.py::test_e05_when_the_faces_differ`에서 본다.
