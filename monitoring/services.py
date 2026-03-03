from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter

from django.db.models import QuerySet
from django.utils import timezone

from monitoring.models import AccessLog, DetectionRun, EvaluationResult, RoleChoices
from monitoring.permissions import get_user_role

try:
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import IsolationForest
except ImportError:  # pragma: no cover
    np = None
    pd = None
    IsolationForest = None


FEATURE_COLUMNS = [
    "access_frequency_per_user",
    "time_of_day_access_deviation",
    "unique_patients_accessed",
    "role_based_access_deviation",
]


@dataclass
class DetectionSummary:
    run_id: int
    total_events: int
    anomalies_flagged: int
    execution_time_ms: float
    contamination: float
    automated_alerts_created: int = 0


def _assert_ml_dependencies() -> None:
    if not all([np, pd, IsolationForest]):
        raise ImportError(
            "Missing ML dependencies. Install packages with "
            "`pip install -r requirements.txt`."
        )


def _safe_role(user) -> str:
    role = get_user_role(user)
    return role if role else RoleChoices.NURSE


def _risk_score_from_model_score(score: float, min_score: float, max_score: float) -> float:
    if max_score <= min_score:
        return 50.0
    normalized = (score - min_score) / (max_score - min_score)
    bounded = max(0.0, min(1.0, float(normalized)))
    return round(bounded * 100.0, 2)


def _severity_from_risk(risk_score: float) -> str:
    if risk_score >= 85:
        return AccessLog.AlertSeverity.CRITICAL
    if risk_score >= 70:
        return AccessLog.AlertSeverity.HIGH
    if risk_score >= 45:
        return AccessLog.AlertSeverity.MEDIUM
    return AccessLog.AlertSeverity.LOW


def _get_client_ip(request) -> str | None:
    if not request:
        return None
    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def log_record_access(
    *,
    user,
    patient_record,
    action: str,
    request=None,
    is_simulated: bool = False,
    is_true_anomaly: bool = False,
    notes: str = "",
    accessed_at=None,
) -> AccessLog:
    return AccessLog.objects.create(
        user=user,
        role_snapshot=_safe_role(user),
        patient_record=patient_record,
        action=action,
        ip_address=_get_client_ip(request),
        user_agent=(request.META.get("HTTP_USER_AGENT", "")[:255] if request else ""),
        is_simulated=is_simulated,
        is_true_anomaly=is_true_anomaly,
        notes=notes[:255],
        accessed_at=accessed_at or timezone.now(),
    )


def build_feature_dataframe(log_queryset: QuerySet[AccessLog]):
    _assert_ml_dependencies()
    rows = list(
        log_queryset.values(
            "id",
            "user_id",
            "role_snapshot",
            "patient_record_id",
            "accessed_at",
        )
    )
    meta = pd.DataFrame(rows)
    if meta.empty:
        empty = pd.DataFrame(columns=FEATURE_COLUMNS)
        return meta, empty

    frame = meta.copy()
    frame["accessed_at"] = pd.to_datetime(frame["accessed_at"], utc=True)
    frame = frame.sort_values("accessed_at").reset_index(drop=True)
    frame["event_date"] = frame["accessed_at"].dt.date
    frame["access_hour"] = frame["accessed_at"].dt.hour.astype(float)

    frame["access_frequency_per_user"] = frame.groupby(["user_id", "event_date"])[
        "id"
    ].transform("count")
    frame["unique_patients_accessed"] = frame.groupby(["user_id", "event_date"])[
        "patient_record_id"
    ].transform("nunique")

    user_hour_avg = frame.groupby("user_id")["access_hour"].transform("mean")
    frame["time_of_day_access_deviation"] = (frame["access_hour"] - user_hour_avg).abs()

    role_day_avg = frame.groupby(["role_snapshot", "event_date"])[
        "access_frequency_per_user"
    ].transform("mean")
    frame["role_based_access_deviation"] = (
        frame["access_frequency_per_user"] - role_day_avg
    ).abs()

    features = frame[FEATURE_COLUMNS].astype(float).fillna(0.0)
    return frame[["id"]], features


def run_isolation_forest_detection(
    log_queryset: QuerySet[AccessLog] | None = None,
    *,
    contamination: float = 0.08,
) -> DetectionSummary:
    _assert_ml_dependencies()
    if log_queryset is None:
        log_queryset = AccessLog.objects.all()
    log_queryset = log_queryset.order_by("accessed_at")

    run = DetectionRun.objects.create(
        started_at=timezone.now(),
        contamination=contamination,
        model_name="IsolationForest",
    )

    meta, features = build_feature_dataframe(log_queryset)
    if features.empty:
        run.finished_at = timezone.now()
        run.total_events_analyzed = 0
        run.anomalies_flagged = 0
        run.execution_time_ms = 0.0
        run.save(
            update_fields=[
                "finished_at",
                "total_events_analyzed",
                "anomalies_flagged",
                "execution_time_ms",
            ]
        )
        return DetectionSummary(
            run_id=run.id,
            total_events=0,
            anomalies_flagged=0,
            execution_time_ms=0.0,
            contamination=contamination,
            automated_alerts_created=0,
        )

    model = IsolationForest(
        n_estimators=120,
        contamination=contamination,
        random_state=42,
        n_jobs=1,
    )

    start = perf_counter()
    model.fit(features)
    predictions = model.predict(features)
    anomaly_scores = -model.score_samples(features)
    execution_time_ms = (perf_counter() - start) * 1000.0

    log_ids = meta["id"].tolist()
    id_to_position = {log_id: idx for idx, log_id in enumerate(log_ids)}
    logs_to_update: list[AccessLog] = []
    score_min = float(anomaly_scores.min())
    score_max = float(anomaly_scores.max())
    automated_alerts_created = 0

    for log in AccessLog.objects.filter(id__in=log_ids):
        position = id_to_position[log.id]
        was_flagged = bool(log.is_flagged)
        previous_status = log.alert_status
        is_flagged = bool(predictions[position] == -1)
        anomaly_score = float(anomaly_scores[position])

        log.is_flagged = is_flagged
        log.anomaly_score = anomaly_score
        if is_flagged:
            risk_score = _risk_score_from_model_score(anomaly_score, score_min, score_max)
            log.risk_score = risk_score
            log.alert_severity = _severity_from_risk(risk_score)
            if log.alert_status != AccessLog.AlertStatus.TRIAGED:
                log.alert_status = AccessLog.AlertStatus.OPEN
            if log.closed_reason:
                log.closed_reason = ""
            if (not was_flagged) or (previous_status == AccessLog.AlertStatus.CLOSED):
                automated_alerts_created += 1
            if not log.notes or log.notes.startswith("auto:"):
                log.notes = (
                    f"auto: IsolationForest run #{run.id} flagged this event "
                    f"(risk={risk_score:.2f})."
                )[:255]
        elif was_flagged and log.alert_status == AccessLog.AlertStatus.OPEN:
            log.alert_status = AccessLog.AlertStatus.CLOSED
            if not log.closed_reason:
                log.closed_reason = "Auto-closed: no longer anomalous in latest run"
        logs_to_update.append(log)

    if logs_to_update:
        AccessLog.objects.bulk_update(
            logs_to_update,
            [
                "is_flagged",
                "anomaly_score",
                "risk_score",
                "alert_severity",
                "alert_status",
                "notes",
                "closed_reason",
            ],
        )

    anomalies_flagged = int((predictions == -1).sum())
    total_events = len(log_ids)
    run.finished_at = timezone.now()
    run.total_events_analyzed = total_events
    run.anomalies_flagged = anomalies_flagged
    run.execution_time_ms = execution_time_ms
    run.save(
        update_fields=[
            "finished_at",
            "total_events_analyzed",
            "anomalies_flagged",
            "execution_time_ms",
        ]
    )

    return DetectionSummary(
        run_id=run.id,
        total_events=total_events,
        anomalies_flagged=anomalies_flagged,
        execution_time_ms=execution_time_ms,
        contamination=contamination,
        automated_alerts_created=automated_alerts_created,
    )


def _safe_divide(numerator: float, denominator: float) -> float:
    return float(numerator / denominator) if denominator else 0.0


def evaluate_detector(
    log_queryset: QuerySet[AccessLog],
    *,
    contamination: float = 0.08,
) -> EvaluationResult:
    summary = run_isolation_forest_detection(log_queryset, contamination=contamination)
    labeled_logs = list(log_queryset.values("is_true_anomaly", "is_flagged"))

    tp = sum(1 for row in labeled_logs if row["is_true_anomaly"] and row["is_flagged"])
    fp = sum(1 for row in labeled_logs if not row["is_true_anomaly"] and row["is_flagged"])
    tn = sum(1 for row in labeled_logs if not row["is_true_anomaly"] and not row["is_flagged"])
    fn = sum(1 for row in labeled_logs if row["is_true_anomaly"] and not row["is_flagged"])

    precision = _safe_divide(tp, tp + fp)
    recall = _safe_divide(tp, tp + fn)
    false_positive_rate = _safe_divide(fp, fp + tn)
    anomaly_detection_rate = _safe_divide(tp, tp + fn)
    predicted_anomalies = tp + fp
    true_anomalies = tp + fn

    return EvaluationResult.objects.create(
        dataset_size=len(labeled_logs),
        true_anomalies=true_anomalies,
        predicted_anomalies=predicted_anomalies,
        precision=precision,
        recall=recall,
        false_positive_rate=false_positive_rate,
        anomaly_detection_rate=anomaly_detection_rate,
        execution_time_ms=summary.execution_time_ms,
        notes=f"Detection run #{summary.run_id} with contamination={contamination}",
    )


def format_evaluation_table(evaluation: EvaluationResult) -> str:
    rows: list[tuple[str, str]] = [
        ("Dataset Size", str(evaluation.dataset_size)),
        ("True Anomalies", str(evaluation.true_anomalies)),
        ("Predicted Anomalies", str(evaluation.predicted_anomalies)),
        ("Precision", f"{evaluation.precision:.4f}"),
        ("Recall", f"{evaluation.recall:.4f}"),
        ("False Positive Rate", f"{evaluation.false_positive_rate:.4f}"),
        ("Anomaly Detection Rate", f"{evaluation.anomaly_detection_rate:.4f}"),
        ("Execution Time (ms)", f"{evaluation.execution_time_ms:.2f}"),
    ]

    key_width = max(len(key) for key, _ in rows)
    value_width = max(len(value) for _, value in rows)
    border = f"+-{'-' * key_width}-+-{'-' * value_width}-+"
    lines = [border]
    for key, value in rows:
        lines.append(f"| {key.ljust(key_width)} | {value.rjust(value_width)} |")
    lines.append(border)
    return "\n".join(lines)
