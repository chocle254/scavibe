"""Stateless signed audit pins used to preserve one Git commit across stages."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
from dataclasses import dataclass


class AuditPinError(RuntimeError):
    """The client did not provide a valid pin for the requested audit session."""


@dataclass(frozen=True)
class AuditPin:
    audit_id: str
    repository_url: str
    app_url: str
    commit_sha: str


@dataclass(frozen=True)
class RampReportToken:
    """A signed, stateless performance-ramp report available after SSE finishes."""

    audit_id: str
    audit_pin: str
    repository: dict[str, object]
    report: dict[str, object]
    measurement: dict[str, object]
    successful_requests: int
    failed_requests: int


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _secret_from_environment() -> bytes:
    value = os.environ.get("SCAVIBE_AUDIT_PIN_SECRET", "").strip()
    if len(value.encode("utf-8")) < 32:
        raise AuditPinError("SCAVIBE_AUDIT_PIN_SECRET must contain at least 32 UTF-8 bytes")
    return value.encode("utf-8")


def issue_audit_pin(*, audit_id: str, repository_url: str, app_url: str, commit_sha: str) -> str:
    payload = json.dumps(
        {"audit_id": audit_id, "repository_url": repository_url, "app_url": app_url, "commit_sha": commit_sha},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    signature = hmac.new(_secret_from_environment(), payload, hashlib.sha256).digest()
    return f"{_encode(payload)}.{_encode(signature)}"


def read_audit_pin(value: str) -> AuditPin:
    try:
        encoded_payload, encoded_signature = value.split(".", 1)
        payload = _decode(encoded_payload)
        signature = _decode(encoded_signature)
    except (ValueError, UnicodeEncodeError, binascii.Error) as error:
        raise AuditPinError("audit_pin is malformed") from error
    expected_signature = hmac.new(_secret_from_environment(), payload, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected_signature):
        raise AuditPinError("audit_pin signature is invalid")
    try:
        parsed = json.loads(payload)
        return AuditPin(
            audit_id=parsed["audit_id"],
            repository_url=parsed["repository_url"],
            app_url=parsed["app_url"],
            commit_sha=parsed["commit_sha"],
        )
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise AuditPinError("audit_pin payload is invalid") from error


def issue_ramp_report_token(
    *,
    audit_id: str,
    audit_pin: str,
    repository: dict[str, object],
    report: dict[str, object],
    measurement: dict[str, object],
    successful_requests: int,
    failed_requests: int,
) -> str:
    """Sign the exact report generated from one completed ramp confirmation."""
    payload = json.dumps(
        {
            "audit_id": audit_id,
            "audit_pin": audit_pin,
            "repository": repository,
            "report": report,
            "measurement": measurement,
            "successful_requests": successful_requests,
            "failed_requests": failed_requests,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    signature = hmac.new(
        _secret_from_environment(),
        b"scavibe-ramp-report-v1\x00" + payload,
        hashlib.sha256,
    ).digest()
    return f"{_encode(payload)}.{_encode(signature)}"


def read_ramp_report_token(value: str) -> RampReportToken:
    try:
        encoded_payload, encoded_signature = value.split(".", 1)
        payload = _decode(encoded_payload)
        signature = _decode(encoded_signature)
    except (ValueError, UnicodeEncodeError, binascii.Error) as error:
        raise AuditPinError("ramp_report_token is malformed") from error
    expected_signature = hmac.new(
        _secret_from_environment(),
        b"scavibe-ramp-report-v1\x00" + payload,
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(signature, expected_signature):
        raise AuditPinError("ramp_report_token signature is invalid")
    try:
        parsed = json.loads(payload)
        return RampReportToken(
            audit_id=parsed["audit_id"],
            audit_pin=parsed["audit_pin"],
            repository=parsed["repository"],
            report=parsed["report"],
            measurement=parsed["measurement"],
            successful_requests=parsed["successful_requests"],
            failed_requests=parsed["failed_requests"],
        )
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise AuditPinError("ramp_report_token payload is invalid") from error
