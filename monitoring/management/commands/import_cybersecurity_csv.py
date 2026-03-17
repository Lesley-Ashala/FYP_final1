from __future__ import annotations

from pathlib import Path

from django.core.management.base import BaseCommand

from monitoring.real_data import import_cybersecurity_csv


class Command(BaseCommand):
    help = "Import real events from cybersecurity.csv into the database."

    def add_arguments(self, parser):
        parser.add_argument(
            "--path",
            default="cybersecurity.csv",
            help="Path to cybersecurity.csv (default: ./cybersecurity.csv)",
        )
        parser.add_argument(
            "--reset",
            action="store_true",
            help="Delete previously imported cybersecurity rows before importing.",
        )

    def handle(self, *args, **options):
        csv_path = Path(options["path"]).resolve()
        result = import_cybersecurity_csv(csv_path=csv_path, reset_existing=bool(options["reset"]))
        if result.rows_read == 0 and result.access_logs_created == 0:
            self.stdout.write(self.style.WARNING("No import performed (already imported or empty)."))
            return
        self.stdout.write(self.style.SUCCESS("Cybersecurity CSV import complete."))
        self.stdout.write(
            f"Rows read: {result.rows_read} | Users created: {result.users_created} | "
            f"Assets created: {result.assets_created} | Access logs created: {result.access_logs_created}"
        )
