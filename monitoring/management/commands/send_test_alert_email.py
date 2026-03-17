from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from monitoring.models import AccessLog
from monitoring.notifications import send_flagged_accesslog_alert


class Command(BaseCommand):
    help = "Send a test Mailjet alert email for a flagged AccessLog (or latest flagged)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--accesslog-id",
            type=int,
            default=0,
            help="AccessLog PK to send for (defaults to latest flagged).",
        )
        parser.add_argument(
            "--run-id",
            type=int,
            default=0,
            help="Optional detection run id to include in the email (defaults to 0).",
        )

    def handle(self, *args, **options):
        accesslog_id = int(options["accesslog_id"] or 0)
        run_id = int(options["run_id"] or 0)

        if accesslog_id:
            log = (
                AccessLog.objects.select_related("user", "patient_record")
                .filter(id=accesslog_id)
                .first()
            )
            if not log:
                raise CommandError(f"AccessLog id={accesslog_id} not found")
        else:
            log = (
                AccessLog.objects.select_related("user", "patient_record")
                .filter(is_flagged=True)
                .order_by("-accessed_at")
                .first()
            )
            if not log:
                raise CommandError("No flagged AccessLog found. Run anomaly detection first.")

        if not log.is_flagged:
            raise CommandError(
                f"AccessLog id={log.id} is not flagged; pick a flagged row or run detection."
            )

        ok = send_flagged_accesslog_alert(access_log=log, detection_run_id=run_id)
        if not ok:
            raise CommandError(
                "Test email not sent. Check env vars: MJ_APIKEY_PUBLIC, MJ_APIKEY_PRIVATE, "
                "MAILJET_FROM_EMAIL (validated), and ALERT_EMAIL_TO. Also check console logs."
            )

        self.stdout.write(self.style.SUCCESS(f"Sent test alert email for AccessLog id={log.id}"))
