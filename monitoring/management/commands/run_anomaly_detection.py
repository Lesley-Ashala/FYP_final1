from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from monitoring.models import AccessLog
from monitoring.services import run_isolation_forest_detection


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

    def handle(self, *args, **options):
        queryset = AccessLog.objects.all().order_by("accessed_at")
        last_hours = options["last_hours"]
        if last_hours > 0:
            cutoff = timezone.now() - timedelta(hours=last_hours)
            queryset = queryset.filter(accessed_at__gte=cutoff)

        summary = run_isolation_forest_detection(
            queryset,
            contamination=options["contamination"],
        )
        self.stdout.write(self.style.SUCCESS("Anomaly detection completed."))
        self.stdout.write(f"- Detection run ID: {summary.run_id}")
        self.stdout.write(f"- Total events analyzed: {summary.total_events}")
        self.stdout.write(f"- Anomalies flagged: {summary.anomalies_flagged}")
        self.stdout.write(f"- Execution time (ms): {summary.execution_time_ms:.2f}")
