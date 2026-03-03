import argparse
import csv
import random
from datetime import time
from pathlib import Path


ROLES = ["doctor", "nurse", "admin"]
ROLE_WEIGHTS = [0.45, 0.45, 0.10]


def _normal_patients(role: str) -> int:
    if role == "doctor":
        return random.randint(1, 6)
    if role == "nurse":
        return random.randint(2, 10)
    return random.randint(1, 4)


def _normal_duration(role: str) -> int:
    if role == "doctor":
        return random.randint(60, 420)
    if role == "nurse":
        return random.randint(90, 600)
    return random.randint(45, 300)


def _normal_access_time(role: str) -> str:
    if role == "doctor":
        hour = random.randint(7, 19)
    elif role == "nurse":
        hour = random.randint(6, 22)
    else:
        hour = random.randint(8, 18)
    minute = random.randint(0, 59)
    return time(hour, minute).strftime("%H:%M")


def _anomalous_patients(role: str) -> int:
    if role == "admin":
        return random.randint(8, 35)
    return random.randint(12, 45)


def _anomalous_duration() -> int:
    return random.randint(700, 3600)


def _anomalous_access_time() -> str:
    hour = random.choice([0, 1, 2, 3, 4, 23])
    minute = random.randint(0, 59)
    return time(hour, minute).strftime("%H:%M")


def generate_dataset(
    output_path: Path,
    *,
    records: int = 10000,
    anomaly_rate: float = 0.10,
    seed: int = 42,
) -> None:
    random.seed(seed)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rows = []
    for _ in range(records):
        role = random.choices(ROLES, weights=ROLE_WEIGHTS, k=1)[0]
        is_anomaly = random.random() < anomaly_rate
        user_id = random.randint(1, 300)

        if not is_anomaly:
            row = {
                "user_id": user_id,
                "role": role,
                "access_time": _normal_access_time(role),
                "patients_accessed": _normal_patients(role),
                "session_duration": _normal_duration(role),
                "label": 0,
            }
        else:
            anomaly_pattern = random.choice(["odd_hour", "high_volume", "long_session"])
            if anomaly_pattern == "odd_hour":
                access_time = _anomalous_access_time()
                patients_accessed = _normal_patients(role)
                session_duration = _normal_duration(role)
            elif anomaly_pattern == "high_volume":
                access_time = _normal_access_time(role)
                patients_accessed = _anomalous_patients(role)
                session_duration = random.randint(400, 1600)
            else:
                access_time = _normal_access_time(role)
                patients_accessed = random.randint(5, 20)
                session_duration = _anomalous_duration()

            row = {
                "user_id": user_id,
                "role": role,
                "access_time": access_time,
                "patients_accessed": patients_accessed,
                "session_duration": session_duration,
                "label": 1,
            }
        rows.append(row)

    with output_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=[
                "user_id",
                "role",
                "access_time",
                "patients_accessed",
                "session_duration",
                "label",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate examiner-friendly synthetic hospital access dataset."
    )
    parser.add_argument("--records", type=int, default=10000)
    parser.add_argument("--anomaly-rate", type=float, default=0.10)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--output",
        type=str,
        default="data/synthetic_hospital_access_10000.csv",
    )
    args = parser.parse_args()

    generate_dataset(
        output_path=Path(args.output),
        records=args.records,
        anomaly_rate=args.anomaly_rate,
        seed=args.seed,
    )
    print(f"Dataset generated: {args.output}")


if __name__ == "__main__":
    main()
