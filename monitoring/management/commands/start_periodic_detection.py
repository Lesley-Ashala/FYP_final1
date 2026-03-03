import time
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from monitoring.models import AccessLog
from monitoring.services import run_isolation_forest_detection


class Command(BaseCommand):
    help = "Continuously run anomaly detection at fixed intervals."

    def add_arguments(self, parser):
        parser.add_argument(
            "--interval-seconds",
            type=int,
            default=300,
            help="Seconds between detection runs.",
        )
        parser.add_argument(
            "--iterations",
            type=int,
            default=0,
            help="Optional max loop count. Use 0 for infinite.",
        )
        parser.add_argument(
            "--contamination",
            type=float,
            default=0.08,
            help="Isolation Forest contamination value.",
        )
        parser.add_argument(
            "--window-hours",
            type=int,
            default=168,
            help="Analyze only logs from the last N hours on each run.",
        )

    def handle(self, *args, **options):
        interval = max(30, options["interval_seconds"])
        iterations = options["iterations"]
        contamination = options["contamination"]
        window_hours = options["window_hours"]

        run_count = 0
        self.stdout.write(
            self.style.WARNING(
                f"Starting periodic detection every {interval}s "
                f"(iterations={'infinite' if iterations == 0 else iterations})."
            )
        )
        try:
            while True:
                cutoff = timezone.now() - timedelta(hours=window_hours)
                queryset = AccessLog.objects.filter(accessed_at__gte=cutoff).order_by("accessed_at")
                summary = run_isolation_forest_detection(
                    queryset,
                    contamination=contamination,
                )
                run_count += 1
                self.stdout.write(
                    f"[Run {run_count}] flagged={summary.anomalies_flagged}/"
                    f"{summary.total_events} in {summary.execution_time_ms:.2f}ms"
                )
                if iterations and run_count >= iterations:
                    break
                time.sleep(interval)
        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING("Periodic detection stopped by user."))
