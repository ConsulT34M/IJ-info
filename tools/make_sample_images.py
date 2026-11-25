#!/usr/bin/env python3
"""수동 확인용 샘플 이미지 생성.

    python tools/make_sample_images.py [--out samples/images] [--extras]

매직바이트가 맞는 작은 PNG/JPG를 FakeFaceMatcher 규칙(2장)에 맞는 파일명으로 만든다.

| 파일명                | FakeFaceMatcher 판정        | 쓰임            |
|----------------------|-----------------------------|-----------------|
| id_card.png          | 얼굴 1개                     | IA-07 정상      |
| selfie.png           | 얼굴 1개, 유사도 95           | IA-09 통과      |
| selfie_mismatch.png  | 얼굴 1개, 유사도 40           | E05 유사도 미달 |
| noface.png           | 얼굴 0개                     | E01 / E04       |
| twofaces.png         | 얼굴 2개                     | E01 / E04       |

`--extras`를 주면 형식 오류 확인용 파일도 만든다(이 셋은 커밋하지 않는다):
`id_card.jpg`, `selfie.jpg`, `not_an_image.png`(매직바이트 불일치 → E01).

기본 5개는 `samples/images/`에 커밋돼 있고, 같은 바이트로 다시 생성된다.
**전부 합성 이미지다. 실제 사람의 사진이 아니다.**
"""

from __future__ import annotations

import argparse
import struct
import zlib
from pathlib import Path

DEFAULT_OUT = Path(__file__).resolve().parents[1] / "samples" / "images"

# 파일명 → 캔버스 색 (내용은 판정에 쓰이지 않는다. 파일명 힌트만 본다)
PNG_FILES = {
    "id_card.png": (210, 220, 235),
    "selfie.png": (235, 215, 205),
    "selfie_mismatch.png": (205, 235, 215),
    "noface.png": (240, 240, 240),
    "twofaces.png": (220, 220, 240),
}
JPG_FILES = ("id_card.jpg", "selfie.jpg")
WIDTH = HEIGHT = 32


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    )


def make_png(color: tuple[int, int, int], width: int = WIDTH, height: int = HEIGHT) -> bytes:
    """단색 PNG를 직접 만든다(외부 라이브러리 없이)."""
    raw = b"".join(b"\x00" + bytes(color) * width for _ in range(height))
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + _png_chunk(b"IDAT", zlib.compress(raw, 9))
        + _png_chunk(b"IEND", b"")
    )


def make_jpg() -> bytes:
    """매직바이트(FF D8 FF)와 최소 구조만 갖춘 아주 작은 JPEG."""
    return bytes.fromhex(
        "ffd8ffe000104a46494600010100000100010000"
        "ffdb004300ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "ffc2000b080001000101011100ffc40014000100000000000000000000000000000009"
        "ffda0008010100003f00d2cf20ffd9"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="샘플 이미지 생성")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument(
        "--extras", action="store_true", help="형식 오류 확인용 파일도 만든다(커밋 대상 아님)"
    )
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    created: list[tuple[str, int]] = []
    for name, color in PNG_FILES.items():
        data = make_png(color)
        (args.out / name).write_bytes(data)
        created.append((name, len(data)))

    if args.extras:
        jpeg = make_jpg()
        for name in JPG_FILES:
            (args.out / name).write_bytes(jpeg)
            created.append((name, len(jpeg)))
        # 확장자만 이미지인 파일 (E01 형식 오류 확인용)
        bogus = b"This is not an image.\n"
        (args.out / "not_an_image.png").write_bytes(bogus)
        created.append(("not_an_image.png", len(bogus)))

    print(f"샘플 이미지 {len(created)}개 → {args.out}")
    for name, size in created:
        print(f"  {name:<22} {size:>6} bytes")
    print("FakeFaceMatcher는 파일명으로 판정한다: noface→0개, twofaces→2개, mismatch→유사도 40.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
