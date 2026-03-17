from django.conf import settings
from django.db import models
from django.utils import timezone


class RoleChoices(models.TextChoices):
    ADMIN = "admin", "Admin"
    DOCTOR = "doctor", "Doctor"
    NURSE = "nurse", "Nurse"


class UserProfile(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="profile",
    )
    role = models.CharField(
        max_length=20,
        choices=RoleChoices.choices,
        default=RoleChoices.NURSE,
    )
    department = models.CharField(max_length=120, blank=True)
    mfa_enabled = models.BooleanField(default=True)
    force_password_reset = models.BooleanField(default=False)

    def __str__(self) -> str:
        return f"{self.user.username} ({self.role})"


class PatientRecord(models.Model):
    hospital_id = models.CharField(max_length=30, unique=True)
    full_name = models.CharField(max_length=200)
    date_of_birth = models.DateField()
    diagnosis = models.TextField()
    notes = models.TextField(blank=True)
    attending_doctor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_patients",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["full_name"]

    def __str__(self) -> str:
        return f"{self.hospital_id} - {self.full_name}"


class AccessLog(models.Model):
    class AccessAction(models.TextChoices):
        VIEW = "view", "View"
        CREATE = "create", "Create"
        UPDATE = "update", "Update"
        DELETE = "delete", "Delete"
        DOWNLOAD = "download", "Download"

    class AlertSeverity(models.TextChoices):
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    class AlertStatus(models.TextChoices):
        OPEN = "open", "Open"
        TRIAGED = "triaged", "Triaged"
        CLOSED = "closed", "Closed"

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="access_logs",
    )
    role_snapshot = models.CharField(max_length=20, choices=RoleChoices.choices)
    patient_record = models.ForeignKey(
        PatientRecord,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="access_logs",
    )
    action = models.CharField(max_length=20, choices=AccessAction.choices)
    accessed_at = models.DateTimeField(default=timezone.now, db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, blank=True)
    is_simulated = models.BooleanField(default=False)
    is_true_anomaly = models.BooleanField(default=False)
    is_flagged = models.BooleanField(default=False, db_index=True)
    anomaly_score = models.FloatField(null=True, blank=True)
    risk_score = models.FloatField(null=True, blank=True)
    alert_severity = models.CharField(
        max_length=20,
        choices=AlertSeverity.choices,
        blank=True,
    )
    alert_status = models.CharField(
        max_length=20,
        choices=AlertStatus.choices,
        default=AlertStatus.OPEN,
    )
    triage_notes = models.TextField(blank=True)
    assigned_investigator = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_access_alerts",
    )
    case_reference = models.CharField(max_length=50, blank=True)
    closed_reason = models.CharField(max_length=255, blank=True)
    notes = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ["-accessed_at"]
        indexes = [
            models.Index(fields=["user", "accessed_at"]),
            models.Index(fields=["role_snapshot", "accessed_at"]),
            models.Index(fields=["is_simulated", "is_true_anomaly"]),
            models.Index(fields=["is_flagged", "alert_status"]),
        ]

    def __str__(self) -> str:
        patient_id = self.patient_record.hospital_id if self.patient_record else "N/A"
        return f"{self.user.username} {self.action} {patient_id} @ {self.accessed_at.isoformat()}"


class DetectionRun(models.Model):
    started_at = models.DateTimeField(default=timezone.now)
    finished_at = models.DateTimeField(null=True, blank=True)
    model_name = models.CharField(max_length=80, default="IsolationForest")
    contamination = models.FloatField(default=0.08)
    total_events_analyzed = models.PositiveIntegerField(default=0)
    anomalies_flagged = models.PositiveIntegerField(default=0)
    execution_time_ms = models.FloatField(default=0.0)

    class Meta:
        ordering = ["-started_at"]

    def __str__(self) -> str:
        return (
            f"{self.model_name} on {self.started_at:%Y-%m-%d %H:%M:%S} "
            f"({self.anomalies_flagged}/{self.total_events_analyzed})"
        )


class EvaluationResult(models.Model):
    created_at = models.DateTimeField(auto_now_add=True)
    dataset_size = models.PositiveIntegerField()
    true_anomalies = models.PositiveIntegerField()
    predicted_anomalies = models.PositiveIntegerField()
    precision = models.FloatField()
    recall = models.FloatField()
    false_positive_rate = models.FloatField()
    anomaly_detection_rate = models.FloatField()
    execution_time_ms = models.FloatField()
    notes = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"Evaluation @ {self.created_at:%Y-%m-%d %H:%M:%S}"


class NursingVital(models.Model):
    patient_record = models.ForeignKey(
        PatientRecord,
        on_delete=models.CASCADE,
        related_name="vitals",
    )
    recorded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="recorded_vitals",
    )
    blood_pressure = models.CharField(max_length=20)
    temperature_c = models.FloatField()
    pulse_bpm = models.PositiveSmallIntegerField()
    respiration_rate = models.PositiveSmallIntegerField()
    oxygen_saturation = models.PositiveSmallIntegerField()
    recorded_at = models.DateTimeField(default=timezone.now, db_index=True)
    notes = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ["-recorded_at"]

    def __str__(self) -> str:
        return f"Vitals {self.patient_record.hospital_id} @ {self.recorded_at:%Y-%m-%d %H:%M}"


class NursingNote(models.Model):
    patient_record = models.ForeignKey(
        PatientRecord,
        on_delete=models.CASCADE,
        related_name="nursing_notes",
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="nursing_notes",
    )
    note_type = models.CharField(max_length=40, default="progress")
    pain_score = models.PositiveSmallIntegerField(null=True, blank=True)
    mobility_status = models.CharField(max_length=120, blank=True)
    intake_output = models.CharField(max_length=120, blank=True)
    escalated_to = models.CharField(max_length=120, blank=True)
    note_text = models.TextField()
    created_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"Note {self.patient_record.hospital_id} @ {self.created_at:%Y-%m-%d %H:%M}"


class InvestigationCase(models.Model):
    class CaseStatus(models.TextChoices):
        OPEN = "open", "Open"
        IN_REVIEW = "in_review", "In Review"
        CLOSED = "closed", "Closed"

    case_reference = models.CharField(max_length=60, unique=True)
    title = models.CharField(max_length=180)
    summary = models.TextField(blank=True)
    status = models.CharField(
        max_length=20,
        choices=CaseStatus.choices,
        default=CaseStatus.OPEN,
    )
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="owned_investigation_cases",
    )
    opened_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="opened_investigation_cases",
    )
    closed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="closed_investigation_cases",
    )
    closed_reason = models.CharField(max_length=255, blank=True)
    opened_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    closed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-opened_at"]

    def __str__(self) -> str:
        return self.case_reference


class InvestigationCaseNote(models.Model):
    case = models.ForeignKey(
        InvestigationCase,
        on_delete=models.CASCADE,
        related_name="notes",
    )
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="investigation_case_notes",
    )
    note = models.TextField()
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.case.case_reference} note"


class AuditEvent(models.Model):
    class Outcome(models.TextChoices):
        SUCCESS = "success", "Success"
        DENIED = "denied", "Denied"

    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_events",
    )
    department = models.CharField(max_length=120, blank=True)
    patient_ref = models.CharField(max_length=30, blank=True)
    action_type = models.CharField(max_length=60)
    target_ref = models.CharField(max_length=100, blank=True)
    details = models.CharField(max_length=255, blank=True)
    outcome = models.CharField(
        max_length=20,
        choices=Outcome.choices,
        default=Outcome.SUCCESS,
    )
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    device = models.CharField(max_length=120, blank=True)

    class Meta:
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["action_type", "timestamp"]),
            models.Index(fields=["department", "timestamp"]),
        ]

    def __str__(self) -> str:
        actor = self.user.username if self.user else "system"
        return f"{self.action_type} by {actor} @ {self.timestamp:%Y-%m-%d %H:%M}"


class SystemSetting(models.Model):
    key = models.CharField(max_length=80, unique=True)
    value = models.TextField()
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="updated_system_settings",
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["key"]

    def __str__(self) -> str:
        return self.key
