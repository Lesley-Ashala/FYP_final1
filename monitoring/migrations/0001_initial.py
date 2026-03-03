# Generated manually for the initial schema.
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="DetectionRun",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("started_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("finished_at", models.DateTimeField(blank=True, null=True)),
                ("model_name", models.CharField(default="IsolationForest", max_length=80)),
                ("contamination", models.FloatField(default=0.08)),
                ("total_events_analyzed", models.PositiveIntegerField(default=0)),
                ("anomalies_flagged", models.PositiveIntegerField(default=0)),
                ("execution_time_ms", models.FloatField(default=0.0)),
            ],
            options={"ordering": ["-started_at"]},
        ),
        migrations.CreateModel(
            name="EvaluationResult",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("dataset_size", models.PositiveIntegerField()),
                ("true_anomalies", models.PositiveIntegerField()),
                ("predicted_anomalies", models.PositiveIntegerField()),
                ("precision", models.FloatField()),
                ("recall", models.FloatField()),
                ("false_positive_rate", models.FloatField()),
                ("anomaly_detection_rate", models.FloatField()),
                ("execution_time_ms", models.FloatField()),
                ("notes", models.CharField(blank=True, max_length=255)),
            ],
            options={"ordering": ["-created_at"]},
        ),
        migrations.CreateModel(
            name="PatientRecord",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("hospital_id", models.CharField(max_length=30, unique=True)),
                ("full_name", models.CharField(max_length=200)),
                ("date_of_birth", models.DateField()),
                ("diagnosis", models.TextField()),
                ("notes", models.TextField(blank=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "attending_doctor",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="assigned_patients",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={"ordering": ["full_name"]},
        ),
        migrations.CreateModel(
            name="UserProfile",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "role",
                    models.CharField(
                        choices=[("doctor", "Doctor"), ("nurse", "Nurse"), ("admin", "Admin")],
                        default="nurse",
                        max_length=20,
                    ),
                ),
                ("department", models.CharField(blank=True, max_length=120)),
                (
                    "user",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="profile",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="AccessLog",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "role_snapshot",
                    models.CharField(
                        choices=[("doctor", "Doctor"), ("nurse", "Nurse"), ("admin", "Admin")],
                        max_length=20,
                    ),
                ),
                (
                    "action",
                    models.CharField(
                        choices=[("view", "View"), ("create", "Create"), ("update", "Update"), ("delete", "Delete")],
                        max_length=20,
                    ),
                ),
                ("accessed_at", models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ("ip_address", models.GenericIPAddressField(blank=True, null=True)),
                ("user_agent", models.CharField(blank=True, max_length=255)),
                ("is_simulated", models.BooleanField(default=False)),
                ("is_true_anomaly", models.BooleanField(default=False)),
                ("is_flagged", models.BooleanField(db_index=True, default=False)),
                ("anomaly_score", models.FloatField(blank=True, null=True)),
                ("notes", models.CharField(blank=True, max_length=255)),
                (
                    "patient_record",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="access_logs",
                        to="monitoring.patientrecord",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="access_logs",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["-accessed_at"],
                "indexes": [
                    models.Index(fields=["user", "accessed_at"], name="monitoring_a_user_id_58b714_idx"),
                    models.Index(fields=["role_snapshot", "accessed_at"], name="monitoring_a_role_sn_00d35b_idx"),
                    models.Index(
                        fields=["is_simulated", "is_true_anomaly"],
                        name="monitoring_a_is_simu_8a1935_idx",
                    ),
                ],
            },
        ),
    ]
