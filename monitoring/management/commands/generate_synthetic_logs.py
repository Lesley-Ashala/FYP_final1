from django.core.management.base import BaseCommand

from monitoring.synthetic import generate_synthetic_access_logs


class Command(BaseCommand):
    help = (
        "Generate a realistic synthetic hospital access-log dataset with "
        "normal and anomalous events."
    )

    def add_arguments(self, parser):
        parser.add_argument("--events", type=int, default=3000, help="Number of access log rows to generate.")
        parser.add_argument(
            "--anomaly-rate",
            type=float,
            default=0.08,
            help="Fraction of events labeled as true anomalies.",
        )
        parser.add_argument("--days", type=int, default=30, help="How many historical days to spread events over.")
        parser.add_argument(
            "--reset-simulated",
            action="store_true",
            help="Delete prior synthetic logs before inserting new rows.",
        )
        parser.add_argument(
            "--export-file",
            type=str,
            default="data/hospital_access_logs.csv",
            help="CSV output path. Use an empty string to skip CSV export.",
        )
        parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducible data.")

    def handle(self, *args, **options):
        export_file = options["export_file"] or None
        result = generate_synthetic_access_logs(
            events=options["events"],
            anomaly_rate=options["anomaly_rate"],
            days=options["days"],
            reset_simulated=options["reset_simulated"],
            export_path=export_file,
            seed=options["seed"],
        )
        self.stdout.write(self.style.SUCCESS("Synthetic dataset generation complete."))
        self.stdout.write(f"- Events generated: {result.total_events}")
        self.stdout.write(f"- True anomalies: {result.anomaly_events}")
        self.stdout.write(f"- Normal events: {result.total_events - result.anomaly_events}")
        if result.csv_path:
            self.stdout.write(f"- CSV exported to: {result.csv_path}")
