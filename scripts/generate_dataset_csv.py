import argparse
import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROLES = ["doctor", "nurse", "admin"]
ROLE_WEIGHTS = [0.45, 0.45, 0.10]
ANOMALY_TYPES = ["odd_hour", "high_frequency_burst", "role_based_deviation"]


def random_hour(role: str, is_anomaly: bool, anomaly_type: str) -> int:
    if is_anomaly and anomaly_type == "odd_hour":
        return random.randint(0, 4)
    if role == "doctor":
        return random.randint(7, 18)
    if role == "nurse":
        return random.randint(6, 21)
    return random.randint(8, 17)


def build_dataset(
    output_file: Path,
    *,
    events: int = 2000,
    anomaly_rate: float = 0.08,
    days: int = 30,
    seed: int = 42,
) -> None:
    random.seed(seed)
    users = {
        "doctor": ["doctor_amy", "doctor_bob", "doctor_lina"],
        "nurse": ["nurse_ella", "nurse_omar", "nurse_sara"],
        "admin": ["admin_mike"],
    }
    patient_ids = [f"P{i:05d}" for i in range(1, 251)]
    now = datetime.now(timezone.utc)
    rows = []

    for _ in range(events):
        role = random.choices(ROLES, weights=ROLE_WEIGHTS, k=1)[0]
        username = random.choice(users[role])
        is_anomaly = random.random() < anomaly_rate
        anomaly_type = random.choice(ANOMALY_TYPES) if is_anomaly else "normal"

        timestamp = now - timedelta(
            days=random.randint(0, max(days - 1, 0)),
            hours=random_hour(role, is_anomaly, anomaly_type),
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59),
        )

        row = {
            "username": username,
            "role": role,
            "patient_hospital_id": random.choice(patient_ids),
            "action": random.choices(["view", "update", "create", "delete"], weights=[84, 10, 4, 2], k=1)[0],
            "accessed_at_utc": timestamp.isoformat().replace("+00:00", "Z"),
            "is_simulated": "true",
            "is_true_anomaly": "true" if is_anomaly else "false",
            "anomaly_type": anomaly_type,
        }
        rows.append(row)

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic hospital access log CSV.")
    parser.add_argument("--events", type=int, default=2000)
    parser.add_argument("--anomaly-rate", type=float, default=0.08)
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=str, default="data/hospital_access_logs.csv")
    args = parser.parse_args()

    build_dataset(
        Path(args.output),
        events=args.events,
        anomaly_rate=args.anomaly_rate,
        days=args.days,
        seed=args.seed,
    )
    print(f"CSV written: {args.output}")


if __name__ == "__main__":
    main()
