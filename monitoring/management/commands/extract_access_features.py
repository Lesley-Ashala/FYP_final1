from datetime import timedelta
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from monitoring.models import AccessLog
from monitoring.services import FEATURE_COLUMNS, build_feature_dataframe


class Command(BaseCommand):
    help = (
        "Extract behavioral features from access logs "
        "(frequency, time deviation, unique patients, role deviation)."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--last-hours",
            type=int,
            default=0,
            help="If set, only extract features for logs from the last N hours.",
        )
        parser.add_argument(
            "--limit",
            type=int,
            default=0,
            help="Optional number of most recent rows to include in the export.",
        )
        parser.add_argument(
            "--output",
            type=str,
            default="data/access_behavior_features.csv",
            help="CSV file path for extracted features. Empty value skips export.",
        )

    def handle(self, *args, **options):
        queryset = AccessLog.objects.order_by("accessed_at")
        if options["last_hours"] > 0:
            cutoff = timezone.now() - timedelta(hours=options["last_hours"])
            queryset = queryset.filter(accessed_at__gte=cutoff)

        if not queryset.exists():
            raise CommandError("No access logs found to extract features from.")

        meta, features = build_feature_dataframe(queryset)
        if features.empty:
            raise CommandError("Feature extraction returned no rows.")

        frame = meta.join(features)
        limit = options["limit"]
        if limit > 0:
            frame = frame.tail(limit)

        output = (options["output"] or "").strip()
        output_path = None
        if output:
            output_path = Path(output)
            if not output_path.is_absolute():
                output_path = Path(settings.BASE_DIR) / output_path
            output_path.parent.mkdir(parents=True, exist_ok=True)
            frame.to_csv(output_path, index=False)

        self.stdout.write(self.style.SUCCESS("Behavioral feature extraction complete."))
        self.stdout.write(f"- Rows extracted: {len(frame)}")
        self.stdout.write(f"- Features: {', '.join(FEATURE_COLUMNS)}")
        if output_path:
            self.stdout.write(f"- CSV exported to: {output_path}")
