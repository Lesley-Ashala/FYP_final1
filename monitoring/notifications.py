from __future__ import annotations

import logging
from typing import Any

from django.conf import settings
from django.template.loader import render_to_string
from django.utils import timezone

from monitoring.models import AccessLog

logger = logging.getLogger(__name__)

_LOG_ONCE: set[str] = set()


def _log_once(key: str, level: int, message: str) -> None:
    if key in _LOG_ONCE:
        return
    _LOG_ONCE.add(key)
    logger.log(level, message)


def _mailjet_client():
    try:
        from mailjet_rest import Client  # type: ignore
    except Exception:  # pragma: no cover
        _log_once(
            "mailjet-lib-missing",
            logging.WARNING,
            "mailjet-rest library not installed; alert emails cannot be sent.",
        )
        return None

    api_key = getattr(settings, "MAILJET_API_KEY_PUBLIC", "")
    api_secret = getattr(settings, "MAILJET_API_KEY_PRIVATE", "")
    if not api_key or not api_secret:
        _log_once(
            "mailjet-keys-missing",
            logging.WARNING,
            "Mailjet API keys missing; set MJ_APIKEY_PUBLIC and MJ_APIKEY_PRIVATE to send alert emails.",
        )
        return None

    return Client(auth=(api_key, api_secret), version="v3.1")


def _build_message_payload(*, subject: str, html: str, text: str) -> dict[str, Any]:
    from_email = getattr(settings, "MAILJET_FROM_EMAIL", "")
    from_name = getattr(settings, "MAILJET_FROM_NAME", "Hospital Monitor")
    if not from_email:
        raise ValueError(
            "MAILJET_FROM_EMAIL is required (and must be validated in Mailjet)."
        )

    recipients = list(getattr(settings, "ALERT_EMAIL_TO", []) or [])
    if not recipients:
        raise ValueError("ALERT_EMAIL_TO has no recipients.")

    return {
        "Messages": [
            {
                "From": {"Email": from_email, "Name": from_name},
                "To": [{"Email": email} for email in recipients],
                "Subject": subject,
                "TextPart": text,
                "HTMLPart": html,
            }
        ]
    }


def send_flagged_accesslog_alert(*, access_log: AccessLog, detection_run_id: int) -> bool:
    """Send a styled security alert email for a flagged access event.

    Returns True if sent successfully; False if disabled or failed.
    """

    enabled = bool(getattr(settings, "ALERT_EMAIL_ENABLED", False))
    if not enabled:
        _log_once(
            "alert-email-disabled",
            logging.INFO,
            "ALERT_EMAIL_ENABLED is false; skipping alert email.",
        )
        return False

    client = _mailjet_client()
    if client is None:
        return False

    alert_id = f"ALT-{access_log.id:05d}"
    severity = (access_log.alert_severity or AccessLog.AlertSeverity.MEDIUM).upper()
    ts = timezone.localtime(access_log.accessed_at)
    patient_id = access_log.patient_record.hospital_id if access_log.patient_record else "N/A"
    username = getattr(access_log.user, "username", "unknown")

    subject = f"[{severity}] Flagged access event {alert_id} • {username} • {access_log.action} {patient_id}"

    context = {
        "alert_id": alert_id,
        "severity": severity,
        "access_log": access_log,
        "detection_run_id": detection_run_id,
        "timestamp_local": ts,
        "timestamp_utc": access_log.accessed_at,
    }

    html = render_to_string("email/monitoring/flagged_accesslog_alert.html", context)
    text = render_to_string("email/monitoring/flagged_accesslog_alert.txt", context)

    try:
        payload = _build_message_payload(subject=subject, html=html, text=text)
    except Exception:
        logger.exception("Alert email payload build failed")
        return False

    try:
        result = client.send.create(data=payload)
        ok = 200 <= int(getattr(result, "status_code", 0) or 0) < 300
        if not ok:
            logger.error(
                "Mailjet send failed status=%s response=%s",
                getattr(result, "status_code", None),
                getattr(result, "json", lambda: None)(),
            )
        else:
            logger.info("Mailjet alert email sent for AccessLog id=%s", access_log.id)
        return ok
    except Exception:
        logger.exception("Mailjet send exception")
        return False
