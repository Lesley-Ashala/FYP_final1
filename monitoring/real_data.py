from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path

from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone

from monitoring.models import AccessLog, PatientRecord, RoleChoices


User = get_user_model()


DATASET_MARKER = "ds=cybersecurity"


@dataclass
class ImportResult:
    rows_read: int
    users_created: int
    assets_created: int
    access_logs_created: int


def _username_for_ip(ip: str) -> str:
    safe = (ip or "unknown").strip().replace(".", "_").replace(":", "_")
    return f"ip_{safe}"[:150]


def _asset_id(dst_ip: str, dst_port: str) -> str:
    digits = (dst_ip or "0.0.0.0").replace(".", "")
    port = str(dst_port or "0")
    # Fits within PatientRecord.hospital_id (max_length=30)
    return f"ASSET-{digits}-{port}"[:30]


def _parse_bool(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "t", "yes", "y"}


def _parse_int(value: str) -> int:
    try:
        return int(str(value).strip() or "0")
    except (TypeError, ValueError):
        return 0


def _parse_timestamp(value: str):
    raw = (value or "").strip()
    if not raw:
        return timezone.now()
    # Example: 2025-10-01 00:12:54
    dt = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
    if timezone.is_naive(dt):
        return timezone.make_aware(dt, timezone.get_current_timezone())
    return dt


def _severity_and_risk(*, label: bool, attack_type: str) -> tuple[str, float, float]:
    if not label:
        return "", 0.0, 0.0

    attack = (attack_type or "").strip().lower()
    if attack in {"ransomware", "data-exfiltration", "credential-theft"}:
        return AccessLog.AlertSeverity.CRITICAL, 98.0, 0.98
    if attack in {"ddos", "bruteforce", "sql-injection"}:
        return AccessLog.AlertSeverity.HIGH, 88.0, 0.88
    if attack in {"port-scan", "scan", "recon"}:
        return AccessLog.AlertSeverity.MEDIUM, 72.0, 0.72

    return AccessLog.AlertSeverity.HIGH, 85.0, 0.85


@transaction.atomic
def import_cybersecurity_csv(
    *,
    csv_path: str | Path,
    reset_existing: bool = False,
) -> ImportResult:
    """Import rows from cybersecurity.csv into AccessLog.

    This adapts the network dataset into the existing hospital-centric schema:
    - src_ip -> user (one Django user per unique src_ip)
    - dst_ip + dst_port -> PatientRecord (treated as an "endpoint/asset")
    - label -> is_true_anomaly and (by default) is_flagged

    Imported rows are tagged by AccessLog.notes containing DATASET_MARKER.
    """

    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"CSV not found: {path}")

    if reset_existing:
        AccessLog.objects.filter(notes__contains=DATASET_MARKER).delete()

    # Avoid re-import if already present.
    if AccessLog.objects.filter(notes__contains=DATASET_MARKER).exists():
        return ImportResult(rows_read=0, users_created=0, assets_created=0, access_logs_created=0)

    users_created = 0
    assets_created = 0
    access_logs: list[AccessLog] = []

    # Local caches to reduce DB chatter.
    user_cache: dict[str, User] = {}
    asset_cache: dict[str, PatientRecord] = {}

    with path.open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        rows_read = 0
        for row in reader:
            rows_read += 1
            src_ip = (row.get("src_ip") or "").strip()
            dst_ip = (row.get("dst_ip") or "").strip()
            dst_port = str(row.get("dst_port") or "").strip()

            username = _username_for_ip(src_ip)
            user = user_cache.get(username)
            if user is None:
                user, created = User.objects.get_or_create(
                    username=username,
                    defaults={
                        "first_name": "Network",
                        "last_name": "Actor",
                        "email": "",
                        "is_active": True,
                        "is_staff": False,
                        "is_superuser": False,
                    },
                )
                if created:
                    users_created += 1
                    user.set_unusable_password()
                    user.save(update_fields=["password"])
                user_cache[username] = user

            asset_id = _asset_id(dst_ip, dst_port)
            asset = asset_cache.get(asset_id)
            if asset is None:
                asset, created = PatientRecord.objects.get_or_create(
                    hospital_id=asset_id,
                    defaults={
                        "full_name": f"Endpoint {dst_ip}:{dst_port}"[:200],
                        "date_of_birth": date(2000, 1, 1),
                        "diagnosis": "Imported network endpoint",
                        "notes": "Imported from cybersecurity.csv",
                        "attending_doctor": None,
                    },
                )
                if created:
                    assets_created += 1
                asset_cache[asset_id] = asset

            label = str(row.get("label") or "0").strip() in {"1", "true", "True"}
            attack_type = (row.get("attack_type") or "").strip()
            severity, risk_score, anomaly_score = _severity_and_risk(label=label, attack_type=attack_type)

            accessed_at = _parse_timestamp(row.get("timestamp") or "")
            protocol = (row.get("protocol") or "").strip().upper()
            bytes_sent = _parse_int(row.get("bytes_sent"))
            bytes_received = _parse_int(row.get("bytes_received"))
            url = (row.get("url") or "").strip()
            internal = _parse_bool(row.get("is_internal_traffic") or "")
            user_agent = (row.get("user_agent") or "").strip()[:255]

            note = (
                f"{DATASET_MARKER} proto={protocol} dst={dst_ip}:{dst_port} "
                f"bytes={bytes_sent}/{bytes_received} attack={attack_type or '-'} "
                f"internal={'1' if internal else '0'} url={(url or '-')[:60]}"
            )[:255]

            access_logs.append(
                AccessLog(
                    user=user,
                    role_snapshot=RoleChoices.NURSE,
                    patient_record=asset,
                    action=AccessLog.AccessAction.VIEW,
                    accessed_at=accessed_at,
                    ip_address=src_ip or None,
                    user_agent=user_agent,
                    is_simulated=False,
                    is_true_anomaly=label,
                    is_flagged=label,
                    anomaly_score=anomaly_score if label else None,
                    risk_score=risk_score if label else None,
                    alert_severity=severity if label else "",
                    alert_status=AccessLog.AlertStatus.OPEN,
                    notes=note,
                )
            )

            if len(access_logs) >= 1000:
                AccessLog.objects.bulk_create(access_logs, batch_size=1000)
                access_logs.clear()

        if access_logs:
            AccessLog.objects.bulk_create(access_logs, batch_size=1000)

    created_count = AccessLog.objects.filter(notes__contains=DATASET_MARKER).count()
    return ImportResult(
        rows_read=rows_read,
        users_created=users_created,
        assets_created=assets_created,
        access_logs_created=created_count,
    )
