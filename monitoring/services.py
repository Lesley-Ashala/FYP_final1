from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from time import perf_counter

from django.db.models import QuerySet
from django.utils import timezone

from monitoring.models import AccessLog, DetectionRun, EvaluationResult, RoleChoices
from monitoring.notifications import send_flagged_accesslog_alert
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


@dataclass
class IsolationForestScores:
    train_ids: list[int]
    test_ids: list[int]
    train_scores: "np.ndarray"
    test_scores: "np.ndarray"
    test_predictions: "np.ndarray"
    execution_time_ms: float


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


def _normalize_threshold_quantile(threshold_quantile: float | None) -> float | None:
    if threshold_quantile is None:
        return None
    quantile = float(threshold_quantile)
    if quantile <= 0.0 or quantile >= 1.0:
        raise ValueError("threshold_quantile must be between 0 and 1 (exclusive).")
    return quantile


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


def flag_download_burst_if_needed(
    *,
    user,
    window_minutes: int = 10,
    threshold: int = 10,
    lock_minutes: int = 10,
) -> bool:
    """Flag rapid successive downloads by the same user.

    When a user downloads many records within a short time window, we flag the
    most recent download event as suspicious and open/reopen an alert.
    """
    if not user or not getattr(user, "is_authenticated", False):
        return False
    if window_minutes <= 0 or threshold <= 1:
        return False

    now = timezone.now()
    start = now - timedelta(minutes=window_minutes)
    recent = (
        AccessLog.objects.filter(
            user=user,
            action=AccessLog.AccessAction.DOWNLOAD,
            accessed_at__gte=start,
        )
        .order_by("-accessed_at")
    )
    download_count = recent.count()
    if download_count < threshold:
        return False

    # Start a cooldown lock once the threshold is reached.
    try:
        profile = getattr(user, "profile", None)
        if profile is not None and lock_minutes > 0:
            locked_until = getattr(profile, "download_locked_until", None)
            if not locked_until or locked_until <= now:
                profile.download_locked_until = now + timedelta(minutes=int(lock_minutes))
                profile.download_lock_reason = (
                    f"Auto-lock: {download_count} downloads in {window_minutes} minutes"
                )[:255]
                profile.save(update_fields=["download_locked_until", "download_lock_reason"])
    except Exception:
        pass

    latest = recent.first()
    if not latest:
        return False
    if latest.is_flagged and (latest.notes or "").lower().startswith("download burst"):
        return False

    # Risk increases with burst size.
    overflow = max(0, download_count - threshold)
    risk_score = min(99.0, 75.0 + overflow * 2.5)
    severity = AccessLog.AlertSeverity.CRITICAL if download_count >= threshold * 2 else AccessLog.AlertSeverity.HIGH
    latest.is_flagged = True
    latest.anomaly_score = round(risk_score / 100.0, 4)
    latest.risk_score = round(risk_score, 2)
    latest.alert_severity = severity
    latest.alert_status = AccessLog.AlertStatus.OPEN
    latest.notes = (
        f"Download burst: {download_count} records in {window_minutes} minutes"
    )[:255]
    latest.save(
        update_fields=[
            "is_flagged",
            "anomaly_score",
            "risk_score",
            "alert_severity",
            "alert_status",
            "notes",
        ]
    )

    # Notify only once per flagged burst event.
    try:
        send_flagged_accesslog_alert(access_log=latest, detection_run_id=0)
    except Exception:
        pass
    return True


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Compute four behavioral features per user-role from access logs.

    Returns one row per (user_id, role_snapshot):
    - access_frequency_per_user
    - time_of_day_access_deviation (hour std)
    - unique_patients_accessed
    - role_based_access_deviation (z-score vs role peer frequency)
    """
    _assert_ml_dependencies()
    frame = df.copy()
    if frame.empty:
        return pd.DataFrame(
            columns=[
                "user_id",
                "role_snapshot",
                *FEATURE_COLUMNS,
            ]
        )

    frame["accessed_at"] = pd.to_datetime(frame["accessed_at"], utc=True, errors="coerce")
    frame["hour"] = frame["accessed_at"].dt.hour
    frame = frame.dropna(subset=["user_id", "role_snapshot", "patient_record_id", "hour"])
    if frame.empty:
        return pd.DataFrame(
            columns=[
                "user_id",
                "role_snapshot",
                *FEATURE_COLUMNS,
            ]
        )

    features = (
        frame.groupby(["user_id", "role_snapshot"], as_index=False)
        .agg(
            access_frequency_per_user=("id", "count"),
            time_of_day_access_deviation=("hour", "std"),
            unique_patients_accessed=("patient_record_id", "nunique"),
        )
        .reset_index(drop=True)
    )

    # std() is NaN for users with a single event; treat as zero hour variance.
    features["time_of_day_access_deviation"] = features["time_of_day_access_deviation"].fillna(0.0)

    role_means = features.groupby("role_snapshot")["access_frequency_per_user"].transform("mean")
    role_stds = (
        features.groupby("role_snapshot")["access_frequency_per_user"]
        .transform("std")
        .replace(0, 1)
        .fillna(1)
    )
    features["role_based_access_deviation"] = (
        (features["access_frequency_per_user"] - role_means) / role_stds
    )

    return features[
        [
            "user_id",
            "role_snapshot",
            "access_frequency_per_user",
            "time_of_day_access_deviation",
            "unique_patients_accessed",
            "role_based_access_deviation",
        ]
    ]


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
    frame["accessed_at"] = pd.to_datetime(frame["accessed_at"], utc=True, errors="coerce")
    frame = frame.sort_values("accessed_at").reset_index(drop=True)
    user_features = extract_features(frame)
    if user_features.empty:
        empty = pd.DataFrame(columns=FEATURE_COLUMNS)
        return frame[["id"]], empty

    event_level = frame.merge(
        user_features,
        on=["user_id", "role_snapshot"],
        how="left",
    )
    features = event_level[FEATURE_COLUMNS].astype(float).fillna(0.0)
    return event_level[["id"]], features


def score_isolation_forest(
    train_queryset: QuerySet[AccessLog],
    test_queryset: QuerySet[AccessLog],
    *,
    contamination: float = 0.08,
) -> IsolationForestScores:
    _assert_ml_dependencies()
    train_meta, train_features = build_feature_dataframe(train_queryset.order_by("accessed_at"))
    test_meta, test_features = build_feature_dataframe(test_queryset.order_by("accessed_at"))
    if train_features.empty:
        raise ValueError("Train split is empty after feature extraction.")
    if test_features.empty:
        raise ValueError("Test split is empty after feature extraction.")

    model = IsolationForest(
        n_estimators=120,
        contamination=contamination,
        random_state=42,
        n_jobs=1,
    )

    train_matrix = train_features[FEATURE_COLUMNS].to_numpy(dtype=float, copy=False)
    test_matrix = test_features[FEATURE_COLUMNS].to_numpy(dtype=float, copy=False)

    start = perf_counter()
    model.fit(train_matrix)
    train_decision = model.decision_function(train_matrix)
    test_decision = model.decision_function(test_matrix)
    # Higher anomaly_scores indicate more anomalous behavior.
    train_scores = -train_decision
    test_scores = -test_decision
    # Default Isolation Forest boundary corresponds to decision_function == 0.
    test_predictions = np.where(test_scores >= 0.0, -1, 1)
    execution_time_ms = (perf_counter() - start) * 1000.0

    return IsolationForestScores(
        train_ids=train_meta["id"].astype(int).tolist(),
        test_ids=test_meta["id"].astype(int).tolist(),
        train_scores=train_scores,
        test_scores=test_scores,
        test_predictions=test_predictions,
        execution_time_ms=execution_time_ms,
    )


def run_isolation_forest_detection(
    log_queryset: QuerySet[AccessLog] | None = None,
    *,
    contamination: float = 0.08,
    threshold_quantile: float | None = None,
) -> DetectionSummary:
    _assert_ml_dependencies()
    threshold_quantile = _normalize_threshold_quantile(threshold_quantile)
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

    feature_matrix = features[FEATURE_COLUMNS].to_numpy(dtype=float, copy=False)

    start = perf_counter()
    model.fit(feature_matrix)
    decision_scores = model.decision_function(feature_matrix)
    # Convert to anomaly-oriented scale (higher = more anomalous).
    anomaly_scores = -decision_scores
    execution_time_ms = (perf_counter() - start) * 1000.0
    if threshold_quantile is None:
        score_threshold = 0.0
    else:
        score_threshold = float(np.quantile(anomaly_scores, threshold_quantile))
    is_flagged_mask = anomaly_scores >= score_threshold

    log_ids = meta["id"].tolist()
    id_to_position = {log_id: idx for idx, log_id in enumerate(log_ids)}
    logs_to_update: list[AccessLog] = []
    logs_to_email: list[AccessLog] = []
    score_min = float(anomaly_scores.min())
    score_max = float(anomaly_scores.max())
    automated_alerts_created = 0

    for log in (
        AccessLog.objects.select_related("user", "patient_record").filter(id__in=log_ids)
    ):
        position = id_to_position[log.id]
        was_flagged = bool(log.is_flagged)
        previous_status = log.alert_status
        is_flagged = bool(is_flagged_mask[position])
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
                logs_to_email.append(log)
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

    if logs_to_email:
        for log in logs_to_email:
            send_flagged_accesslog_alert(access_log=log, detection_run_id=run.id)

    anomalies_flagged = int(is_flagged_mask.sum())
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
    threshold_quantile: float | None = None,
) -> EvaluationResult:
    summary = run_isolation_forest_detection(
        log_queryset,
        contamination=contamination,
        threshold_quantile=threshold_quantile,
    )
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
        notes=(
            f"Detection run #{summary.run_id} with contamination={contamination}"
            + (
                f", threshold_quantile={threshold_quantile:.4f}"
                if threshold_quantile is not None
                else ""
            )
        ),
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
