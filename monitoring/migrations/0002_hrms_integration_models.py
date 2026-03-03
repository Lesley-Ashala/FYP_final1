from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("monitoring", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="userprofile",
            name="force_password_reset",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="userprofile",
            name="mfa_enabled",
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name="accesslog",
            name="alert_severity",
            field=models.CharField(
                blank=True,
                choices=[
                    ("low", "Low"),
                    ("medium", "Medium"),
                    ("high", "High"),
                    ("critical", "Critical"),
                ],
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name="accesslog",
            name="alert_status",
            field=models.CharField(
                choices=[("open", "Open"), ("triaged", "Triaged"), ("closed", "Closed")],
                default="open",
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name="accesslog",
            name="case_reference",
            field=models.CharField(blank=True, max_length=50),
        ),
        migrations.AddField(
            model_name="accesslog",
            name="closed_reason",
            field=models.CharField(blank=True, max_length=255),
        ),
        migrations.AddField(
            model_name="accesslog",
            name="risk_score",
            field=models.FloatField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="accesslog",
            name="triage_notes",
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name="accesslog",
            name="assigned_investigator",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="assigned_access_alerts",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddIndex(
            model_name="accesslog",
            index=models.Index(fields=["is_flagged", "alert_status"], name="monitoring_a_is_fla_d97689_idx"),
        ),
        migrations.CreateModel(
            name="AuditEvent",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("timestamp", models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ("department", models.CharField(blank=True, max_length=120)),
                ("patient_ref", models.CharField(blank=True, max_length=30)),
                ("action_type", models.CharField(max_length=60)),
                ("target_ref", models.CharField(blank=True, max_length=100)),
                ("details", models.CharField(blank=True, max_length=255)),
                ("outcome", models.CharField(choices=[("success", "Success"), ("denied", "Denied")], default="success", max_length=20)),
                ("ip_address", models.GenericIPAddressField(blank=True, null=True)),
                ("device", models.CharField(blank=True, max_length=120)),
                (
                    "user",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="audit_events",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={"ordering": ["-timestamp"]},
        ),
        migrations.AddIndex(
            model_name="auditevent",
            index=models.Index(fields=["action_type", "timestamp"], name="monitoring_a_action__fd2739_idx"),
        ),
        migrations.AddIndex(
            model_name="auditevent",
            index=models.Index(fields=["department", "timestamp"], name="monitoring_a_departm_a82f25_idx"),
        ),
        migrations.CreateModel(
            name="InvestigationCase",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("case_reference", models.CharField(max_length=60, unique=True)),
                ("title", models.CharField(max_length=180)),
                ("summary", models.TextField(blank=True)),
                ("status", models.CharField(choices=[("open", "Open"), ("in_review", "In Review"), ("closed", "Closed")], default="open", max_length=20)),
                ("closed_reason", models.CharField(blank=True, max_length=255)),
                ("opened_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("closed_at", models.DateTimeField(blank=True, null=True)),
                (
                    "closed_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="closed_investigation_cases",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "opened_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="opened_investigation_cases",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "owner",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="owned_investigation_cases",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={"ordering": ["-opened_at"]},
        ),
        migrations.CreateModel(
            name="NursingNote",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("note_type", models.CharField(default="progress", max_length=40)),
                ("pain_score", models.PositiveSmallIntegerField(blank=True, null=True)),
                ("mobility_status", models.CharField(blank=True, max_length=120)),
                ("intake_output", models.CharField(blank=True, max_length=120)),
                ("escalated_to", models.CharField(blank=True, max_length=120)),
                ("note_text", models.TextField()),
                ("created_at", models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="nursing_notes",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "patient_record",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="nursing_notes",
                        to="monitoring.patientrecord",
                    ),
                ),
            ],
            options={"ordering": ["-created_at"]},
        ),
        migrations.CreateModel(
            name="NursingVital",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("blood_pressure", models.CharField(max_length=20)),
                ("temperature_c", models.FloatField()),
                ("pulse_bpm", models.PositiveSmallIntegerField()),
                ("respiration_rate", models.PositiveSmallIntegerField()),
                ("oxygen_saturation", models.PositiveSmallIntegerField()),
                ("recorded_at", models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ("notes", models.CharField(blank=True, max_length=255)),
                (
                    "patient_record",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="vitals",
                        to="monitoring.patientrecord",
                    ),
                ),
                (
                    "recorded_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="recorded_vitals",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={"ordering": ["-recorded_at"]},
        ),
        migrations.CreateModel(
            name="SystemSetting",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("key", models.CharField(max_length=80, unique=True)),
                ("value", models.TextField()),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "updated_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="updated_system_settings",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={"ordering": ["key"]},
        ),
        migrations.CreateModel(
            name="InvestigationCaseNote",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("note", models.TextField()),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now)),
                (
                    "author",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="investigation_case_notes",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "case",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="notes",
                        to="monitoring.investigationcase",
                    ),
                ),
            ],
            options={"ordering": ["-created_at"]},
        ),
    ]
