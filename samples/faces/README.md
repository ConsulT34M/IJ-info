# samples/faces — 실제 얼굴 사진 (git에 올리지 않는다)

`FACE_MATCHER=local` 로 돌릴 때 쓸 사진을 여기에 둡니다. **이미지 파일은 gitignore 대상**입니다.

## 왜 따로 필요한가

`samples/images/` 의 샘플은 **매직바이트만 맞춘 합성 단색 이미지**라 얼굴이 들어 있지 않습니다.
`FakeFaceMatcher`(기본값)는 파일명만 보기 때문에 그걸로도 통과하지만,
`LocalFaceMatcher`와 AWS `Rekognition`은 **이미지를 실제로 보기 때문에** 얼굴 0개로 판정합니다(E04).

그래서 local·rekognition 모드를 확인하려면 **진짜 얼굴이 찍힌 사진**이 필요합니다.

## 무엇을 두면 되나

| 파일 | 용도 |
|---|---|
| `id_card.jpg` | 신분증 사진 자리. 얼굴 1개가 또렷하게 보이는 정면 사진 |
| `selfie.jpg` | 같은 사람의 다른 사진. 일치 경로 확인용 |
| `selfie_other.jpg` | **다른 사람** 사진. E05(유사도 미달) 확인용 |
| `noface.jpg` | 풍경·사물·동물 사진. E04(얼굴 미검출) 확인용 |

## 주의

- **실제 타인의 사진을 동의 없이 쓰지 않습니다.** 본인 사진이나 생성된 얼굴
  (예: 공개된 합성 얼굴 데이터셋)을 씁니다.
- 어떤 경우에도 **커밋하지 않습니다.** `.gitignore`가 이 폴더의 이미지를 막고 있습니다.
- 진단·발표가 끝나면 지웁니다.

## 쓰는 법

```bash
uv pip install -r requirements-optional.txt     # opencv-python-headless
echo "FACE_MATCHER=local" >> .env
.venv/bin/flask run
```
