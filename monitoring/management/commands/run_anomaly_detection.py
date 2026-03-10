from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from monitoring.models import AccessLog
from monitoring.services import extract_features, run_isolation_forest_detection

try:
    import pandas as pd
except ImportError:  # pragma: no cover
    pd = None


class Command(BaseCommand):
    help = "Run Isolation Forest anomaly detection on access logs."

    def add_arguments(self, parser):
        parser.add_argument(
            "--contamination",
            type=float,
            default=0.08,
            help="Expected anomaly proportion used by Isolation Forest.",
        )
        parser.add_argument(
            "--last-hours",
            type=int,
            default=0,
            help="If set, only analyze logs from the last N hours.",
        )
        parser.add_argument(
            "--threshold-quantile",
            type=float,
            default=None,
            help=(
                "Optional quantile threshold on anomaly scores (0-1), "
                "e.g. 0.95 flags top 5 percent most abnormal events."
            ),
        )
        parser.add_argument(
            "--show-user-features",
            action="store_true",
            help="Print computed feature vector per user before running detection.",
        )
        parser.add_argument(
            "--feature-limit",
            type=int,
            default=0,
            help="Optional max number of user feature rows to print (0 = all).",
        )

    def handle(self, *args, **options):
        threshold_quantile = options["threshold_quantile"]
        if threshold_quantile is not None and not (0.0 < threshold_quantile < 1.0):
            raise CommandError("--threshold-quantile must be between 0 and 1 (exclusive).")

        queryset = AccessLog.objects.all().order_by("accessed_at")
        last_hours = options["last_hours"]
        if last_hours > 0:
            cutoff = timezone.now() - timedelta(hours=last_hours)
            queryset = queryset.filter(accessed_at__gte=cutoff)

        if options["show_user_features"]:
            if pd is None:
                raise CommandError("Pandas is required to print feature vectors.")
            rows = list(
                queryset.values(
                    "id",
                    "user_id",
                    "role_snapshot",
                    "patient_record_id",
                    "accessed_at",
                )
            )
            frame = pd.DataFrame(rows)
            user_features = extract_features(frame)
            if user_features.empty:
                self.stdout.write(self.style.WARNING("No user feature vectors available for selected logs."))
            else:
                feature_limit = max(0, int(options["feature_limit"]))
                feature_table = user_features.rename(
                    columns={
                        "access_frequency_per_user": "access_frequency",
                        "time_of_day_access_deviation": "time_deviation",
                        "unique_patients_accessed": "unique_patients",
                        "role_based_access_deviation": "role_deviation",
                    }
                )
                feature_table = feature_table.sort_values(["role_snapshot", "user_id"]).reset_index(drop=True)
                feature_table["access_frequency"] = feature_table["access_frequency"].astype(int)
                feature_table["unique_patients"] = feature_table["unique_patients"].astype(int)
                for column in ("time_deviation", "role_deviation"):
                    feature_table[column] = feature_table[column].astype(float).round(4)
                if feature_limit > 0:
                    feature_table = feature_table.head(feature_limit)
                self.stdout.write("Feature vectors per user (current detection window):")
                self.stdout.write(feature_table.to_string(index=False))
                self.stdout.write("")

        summary = run_isolation_forest_detection(
            queryset,
            contamination=options["contamination"],
            threshold_quantile=threshold_quantile,
        )
        self.stdout.write(self.style.SUCCESS("Anomaly detection completed."))
        self.stdout.write(f"- Detection run ID: {summary.run_id}")
        self.stdout.write(f"- Total events analyzed: {summary.total_events}")
        self.stdout.write(f"- Anomalies flagged: {summary.anomalies_flagged}")
        self.stdout.write(f"- Automated alerts opened/reopened: {summary.automated_alerts_created}")
        self.stdout.write(f"- Execution time (ms): {summary.execution_time_ms:.2f}")
