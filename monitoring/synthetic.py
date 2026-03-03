from __future__ import annotations

import csv
import random
from dataclasses import dataclass
from datetime import datetime, time, timedelta
from pathlib import Path

from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone

from monitoring.models import AccessLog, PatientRecord, RoleChoices, UserProfile


User = get_user_model()

ROLE_WEIGHTS = {
    RoleChoices.DOCTOR: 0.45,
    RoleChoices.NURSE: 0.45,
    RoleChoices.ADMIN: 0.10,
}

NORMAL_HOURS = {
    RoleChoices.DOCTOR: (7, 18),
    RoleChoices.NURSE: (6, 21),
    RoleChoices.ADMIN: (8, 17),
}

ANOMALY_TYPES = [
    "odd_hour",
    "high_frequency_burst",
    "role_based_deviation",
]


@dataclass
class SyntheticGenerationResult:
    total_events: int
    anomaly_events: int
    csv_path: Path | None


def ensure_demo_users() -> dict[str, list[User]]:
    user_specs = [
        ("doctor_amy", "Amy", "Jones", RoleChoices.DOCTOR),
        ("doctor_bob", "Bob", "Smith", RoleChoices.DOCTOR),
        ("doctor_lina", "Lina", "Khan", RoleChoices.DOCTOR),
        ("nurse_ella", "Ella", "Nguyen", RoleChoices.NURSE),
        ("nurse_omar", "Omar", "Ali", RoleChoices.NURSE),
        ("nurse_sara", "Sara", "Chen", RoleChoices.NURSE),
        ("admin_mike", "Mike", "Brown", RoleChoices.ADMIN),
    ]

    by_role: dict[str, list[User]] = {
        RoleChoices.DOCTOR: [],
        RoleChoices.NURSE: [],
        RoleChoices.ADMIN: [],
    }

    for username, first_name, last_name, role in user_specs:
        user, created = User.objects.get_or_create(
            username=username,
            defaults={
                "first_name": first_name,
                "last_name": last_name,
                "email": f"{username}@hospital.local",
                "is_staff": role == RoleChoices.ADMIN,
            },
        )
        if created:
            user.set_password("Hospital123!")
            user.save(update_fields=["password"])

        profile, _ = UserProfile.objects.get_or_create(user=user)
        profile.role = role
        profile.department = (
            "Emergency"
            if role == RoleChoices.DOCTOR
            else "Nursing"
            if role == RoleChoices.NURSE
            else "Records"
        )
        profile.save(update_fields=["role", "department"])
        by_role[role].append(user)

    return by_role


def ensure_patients(total_patients: int = 250) -> list[PatientRecord]:
    existing = PatientRecord.objects.count()
    to_create = max(0, total_patients - existing)

    if to_create:
        first_names = [
            "James",
            "Mary",
            "John",
            "Patricia",
            "Robert",
            "Linda",
            "Michael",
            "Elizabeth",
            "David",
            "Jennifer",
            "Maria",
            "Joseph",
        ]
        last_names = [
            "Smith",
            "Johnson",
            "Williams",
            "Brown",
            "Jones",
            "Miller",
            "Davis",
            "Wilson",
            "Moore",
            "Taylor",
            "Anderson",
            "Thomas",
        ]
        diagnoses = [
            "Hypertension",
            "Type II Diabetes",
            "Asthma",
            "Pneumonia",
            "Post-Operative Care",
            "Cardiac Arrhythmia",
            "Kidney Infection",
            "Migraine",
            "Osteoarthritis",
            "Anemia",
        ]
        batch = []
        start_index = existing + 1
        for idx in range(start_index, start_index + to_create):
            name = f"{random.choice(first_names)} {random.choice(last_names)}"
            dob = timezone.now().date() - timedelta(days=random.randint(18 * 365, 90 * 365))
            batch.append(
                PatientRecord(
                    hospital_id=f"P{idx:05d}",
                    full_name=name,
                    date_of_birth=dob,
                    diagnosis=random.choice(diagnoses),
                    notes="Synthetic patient generated for testing",
                )
            )
        PatientRecord.objects.bulk_create(batch, batch_size=500)

    return list(PatientRecord.objects.all().order_by("hospital_id")[:total_patients])


def _sample_role() -> str:
    roles = list(ROLE_WEIGHTS.keys())
    weights = [ROLE_WEIGHTS[role] for role in roles]
    return random.choices(roles, weights=weights, k=1)[0]


def _random_timestamp(days: int, hour_range: tuple[int, int]) -> datetime:
    now = timezone.now()
    day_offset = random.randint(0, max(days - 1, 0))
    selected_day = (now - timedelta(days=day_offset)).date()
    start_hour, end_hour = hour_range
    hour = random.randint(start_hour, end_hour)
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    naive = datetime.combine(selected_day, time(hour, minute, second))
    return timezone.make_aware(naive, timezone.get_current_timezone())


@transaction.atomic
def generate_synthetic_access_logs(
    *,
    events: int = 3000,
    anomaly_rate: float = 0.08,
    days: int = 30,
    reset_simulated: bool = False,
    export_path: str | None = "data/hospital_access_logs.csv",
    seed: int = 42,
) -> SyntheticGenerationResult:
    random.seed(seed)
    users_by_role = ensure_demo_users()
    patients = ensure_patients()

    if reset_simulated:
        AccessLog.objects.filter(is_simulated=True).delete()

    user_patient_pool: dict[int, list[PatientRecord]] = {}
    for role_users in users_by_role.values():
        for user in role_users:
            user_patient_pool[user.id] = random.sample(patients, k=min(45, len(patients)))

    created_logs: list[AccessLog] = []
    csv_rows: list[dict[str, str | int | float | bool]] = []
    last_access_for_user: dict[int, datetime] = {}
    anomaly_count = 0

    for _ in range(events):
        role = _sample_role()
        user = random.choice(users_by_role[role])
        is_anomaly = random.random() < anomaly_rate
        anomaly_type = "normal"
        hour_range = NORMAL_HOURS[role]

        if is_anomaly:
            anomaly_type = random.choice(ANOMALY_TYPES)
            anomaly_count += 1

        if anomaly_type == "odd_hour":
            access_time = _random_timestamp(days, (0, 4))
        elif anomaly_type == "high_frequency_burst":
            previous = last_access_for_user.get(user.id)
            if previous:
                access_time = previous + timedelta(minutes=random.randint(0, 2))
            else:
                access_time = _random_timestamp(days, hour_range)
        else:
            access_time = _random_timestamp(days, hour_range)

        if anomaly_type == "role_based_deviation":
            patient = random.choice(patients)
        else:
            patient = random.choice(user_patient_pool[user.id])

        action = random.choices(
            [
                AccessLog.AccessAction.VIEW,
                AccessLog.AccessAction.UPDATE,
                AccessLog.AccessAction.CREATE,
                AccessLog.AccessAction.DELETE,
            ],
            weights=[84, 10, 4, 2],
            k=1,
        )[0]

        log = AccessLog(
            user=user,
            role_snapshot=role,
            patient_record=patient,
            action=action,
            accessed_at=access_time,
            ip_address=f"10.{1 if role == RoleChoices.DOCTOR else 2 if role == RoleChoices.NURSE else 3}.{random.randint(0, 254)}.{random.randint(1, 254)}",
            user_agent="SyntheticDataGenerator/1.0",
            is_simulated=True,
            is_true_anomaly=is_anomaly,
            notes=f"synthetic:{anomaly_type}",
        )
        created_logs.append(log)

        csv_rows.append(
            {
                "username": user.username,
                "role": role,
                "patient_hospital_id": patient.hospital_id,
                "action": action,
                "accessed_at": access_time.isoformat(),
                "is_simulated": True,
                "is_true_anomaly": is_anomaly,
                "anomaly_type": anomaly_type,
            }
        )
        last_access_for_user[user.id] = access_time

    AccessLog.objects.bulk_create(created_logs, batch_size=1000)

    path_obj: Path | None = None
    if export_path:
        path_obj = Path(export_path)
        if not path_obj.is_absolute():
            from django.conf import settings

            path_obj = Path(settings.BASE_DIR) / path_obj
        path_obj.parent.mkdir(parents=True, exist_ok=True)
        with path_obj.open("w", newline="", encoding="utf-8") as csvfile:
            if csv_rows:
                writer = csv.DictWriter(csvfile, fieldnames=list(csv_rows[0].keys()))
                writer.writeheader()
                writer.writerows(csv_rows)

    return SyntheticGenerationResult(
        total_events=events,
        anomaly_events=anomaly_count,
        csv_path=path_obj,
    )
