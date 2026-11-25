"""모의 통신사 호출 (MC-01, MC-02).

TLS + 인증서 고정(W-15): 시스템 신뢰 저장소가 아니라 통신사 인증서 파일만 신뢰한다.
응답 없음·오류는 CarrierError로 올리고, 호출부가 P05로 종결한 뒤 503을 돌려준다.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import requests
from flask import current_app

from app.common import secrets as secret_store

REASON_NAME_MISMATCH = "NAME_MISMATCH"
REASON_NOT_SUBSCRIBER = "NOT_SUBSCRIBER"


class CarrierError(RuntimeError):
    """통신사 응답 없음·오류. 호출부는 P05로 종결한다."""


@dataclass(frozen=True)
class MatchResult:
    """MC-01 결과. reason은 내부용이다(D1)."""

    matched: bool
    reason: str | None = None
    match_token: str | None = None
    expires_at: str | None = None


def _ca_bundle() -> str:
    """인증서 고정에 쓸 통신사 인증서 경로."""
    configured = Path(current_app.config["CARRIER_CA_BUNDLE"])
    if not configured.is_absolute():
        configured = Path(current_app.root_path).parent / configured
    if not configured.exists():
        raise CarrierError(f"통신사 인증서가 없다: {configured}")
    return str(configured)


def _post(path: str, payload: dict) -> requests.Response:
    base = current_app.config["CARRIER_BASE_URL"].rstrip("/")
    try:
        return requests.post(
            f"{base}{path}",
            json=payload,
            headers={"X-Carrier-Client-Key": secret_store.get_secret("ekyc/phone/carrier-client-key")},
            timeout=current_app.config["CARRIER_TIMEOUT"],
            verify=_ca_bundle(),
        )
    except requests.RequestException as exc:
        raise CarrierError(f"통신사 호출 실패: {exc.__class__.__name__}") from exc


def identity_match(verification_id, name: str, phone_number: str) -> MatchResult:
    """MC-01. 명의 대조. 일치하면 5분짜리 대조 토큰을 받는다."""
    response = _post(
        "/carrier/v1/identity-matches",
        {"verification_id": str(verification_id), "name": name, "phone_number": phone_number},
    )
    if response.status_code != 200:
        raise CarrierError(f"MC-01 응답 코드 {response.status_code}")
    try:
        body = response.json()
    except ValueError as exc:
        raise CarrierError("MC-01 응답이 JSON이 아니다") from exc

    matched = bool(body.get("matched"))
    if matched and not body.get("match_token"):
        raise CarrierError("MC-01 일치 응답에 대조 토큰이 없다")
    return MatchResult(
        matched=matched,
        reason=body.get("reason"),
        match_token=body.get("match_token"),
        expires_at=body.get("expires_at"),
    )


def issue_ci(verification_id, match_token: str) -> str:
    """MC-02. 대조 토큰으로 CI(88자)를 받는다."""
    response = _post(
        "/carrier/v1/ci-issuances",
        {"verification_id": str(verification_id), "match_token": match_token},
    )
    if response.status_code != 200:
        raise CarrierError(f"MC-02 응답 코드 {response.status_code}")
    try:
        ci = response.json().get("ci")
    except ValueError as exc:
        raise CarrierError("MC-02 응답이 JSON이 아니다") from exc
    if not isinstance(ci, str) or len(ci) != 88:
        raise CarrierError("MC-02 응답의 CI 형식이 올바르지 않다")
    return ci
