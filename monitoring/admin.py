from django.contrib import admin

from monitoring.models import (
    AuditEvent,
    AccessLog,
    DetectionRun,
    EvaluationResult,
    InvestigationCase,
    InvestigationCaseNote,
    NursingNote,
    NursingVital,
    PatientRecord,
    SystemSetting,
    UserProfile,
)


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ("user", "role", "department", "mfa_enabled", "force_password_reset")
    list_filter = ("role", "department")
    search_fields = ("user__username", "department")


@admin.register(PatientRecord)
class PatientRecordAdmin(admin.ModelAdmin):
    list_display = ("hospital_id", "full_name", "date_of_birth", "attending_doctor", "updated_at")
    search_fields = ("hospital_id", "full_name", "diagnosis")
    list_filter = ("attending_doctor",)


@admin.register(AccessLog)
class AccessLogAdmin(admin.ModelAdmin):
    list_display = (
        "accessed_at",
        "user",
        "role_snapshot",
        "patient_record",
        "action",
        "is_flagged",
        "alert_status",
        "alert_severity",
        "is_true_anomaly",
    )
    list_filter = (
        "action",
        "role_snapshot",
        "is_flagged",
        "alert_status",
        "alert_severity",
        "is_true_anomaly",
        "is_simulated",
    )
    search_fields = ("user__username", "patient_record__hospital_id", "notes")
    date_hierarchy = "accessed_at"


@admin.register(DetectionRun)
class DetectionRunAdmin(admin.ModelAdmin):
    list_display = (
        "started_at",
        "model_name",
        "contamination",
        "total_events_analyzed",
        "anomalies_flagged",
        "execution_time_ms",
    )
    readonly_fields = ("started_at", "finished_at")


@admin.register(EvaluationResult)
class EvaluationResultAdmin(admin.ModelAdmin):
    list_display = (
        "created_at",
        "dataset_size",
        "precision",
        "recall",
        "false_positive_rate",
        "anomaly_detection_rate",
        "execution_time_ms",
    )


@admin.register(NursingVital)
class NursingVitalAdmin(admin.ModelAdmin):
    list_display = (
        "recorded_at",
        "patient_record",
        "recorded_by",
        "blood_pressure",
        "temperature_c",
        "pulse_bpm",
        "oxygen_saturation",
    )
    search_fields = ("patient_record__hospital_id", "recorded_by__username")
    date_hierarchy = "recorded_at"


@admin.register(NursingNote)
class NursingNoteAdmin(admin.ModelAdmin):
    list_display = ("created_at", "patient_record", "created_by", "note_type", "pain_score")
    search_fields = ("patient_record__hospital_id", "created_by__username", "note_text")
    date_hierarchy = "created_at"


@admin.register(InvestigationCase)
class InvestigationCaseAdmin(admin.ModelAdmin):
    list_display = ("case_reference", "title", "status", "owner", "opened_at", "closed_at")
    list_filter = ("status",)
    search_fields = ("case_reference", "title", "summary")


@admin.register(InvestigationCaseNote)
class InvestigationCaseNoteAdmin(admin.ModelAdmin):
    list_display = ("case", "author", "created_at")
    search_fields = ("case__case_reference", "author__username", "note")
    date_hierarchy = "created_at"


@admin.register(AuditEvent)
class AuditEventAdmin(admin.ModelAdmin):
    list_display = ("timestamp", "user", "action_type", "patient_ref", "outcome", "department")
    list_filter = ("outcome", "action_type", "department")
    search_fields = ("user__username", "patient_ref", "target_ref", "details")
    date_hierarchy = "timestamp"


@admin.register(SystemSetting)
class SystemSettingAdmin(admin.ModelAdmin):
    list_display = ("key", "value", "updated_by", "updated_at")
    search_fields = ("key",)
