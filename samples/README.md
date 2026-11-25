# 팀원 테스트용 샘플 데이터

**전부 가상 데이터다. 실제 인물이 아니고 실제 사진도 아니다.**
격리된 실습 환경에서만 쓴다. 이 저장소 어디에도 실제 개인정보를 넣지 않는다.

| 파일 | 내용 |
|---|---|
| `people.json` | 가상 인물 10명. 성명은 Faker ko_KR, 주민번호는 **체크섬만 맞춘 가상 값**, 휴대폰번호는 가짜 번호, 수신함 키는 테스트 문자 수신함용. 9번 인물은 진위확인 대장에서 `분실`(E03 확인용) |
| `images/id_card.png` | 신분증 사진 자리(합성 단색 PNG). `FakeFaceMatcher`가 얼굴 1개로 판정 |
| `images/selfie.png` | 얼굴 사진 자리. 유사도 95 → 통과 |
| `images/selfie_mismatch.png` | 유사도 40 → E05(유사도 미달) |
| `images/noface.png` | 얼굴 0개 → E01(신분증) / E04(얼굴) |
| `images/twofaces.png` | 얼굴 2개 → E01(신분증) / E04(얼굴) |

이미지는 내용이 아니라 **파일명**으로 판정이 갈린다(`FakeFaceMatcher` 규칙).
`tools/make_sample_images.py`로 같은 바이트를 다시 만들 수 있고,
`--extras`를 주면 형식 오류 확인용 파일(`not_an_image.png` 등)도 생긴다(커밋 대상 아님).

`bash tools/demo_reset.sh`는 `samples/people.json`이 있으면 그 파일을 그대로 써서
팀원 모두가 **같은 10명**으로 테스트하게 한다. 새로 뽑고 싶으면 `--regen-people`을 준다.
