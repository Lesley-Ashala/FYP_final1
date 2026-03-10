from __future__ import annotations

from collections import defaultdict

from django.core.management.base import BaseCommand, CommandError

from monitoring.models import AccessLog
from monitoring.services import score_isolation_forest

try:
    import numpy as np
except ImportError:  # pragma: no cover
    np = None


def _safe_divide(numerator: float, denominator: float) -> float:
    return float(numerator / denominator) if denominator else 0.0


def _compute_metrics(y_true: "np.ndarray", y_pred: "np.ndarray") -> dict[str, float]:
    tp = int(np.sum(y_true & y_pred))
    fp = int(np.sum(~y_true & y_pred))
    tn = int(np.sum(~y_true & ~y_pred))
    fn = int(np.sum(y_true & ~y_pred))
    precision = _safe_divide(tp, tp + fp)
    recall = _safe_divide(tp, tp + fn)
    false_positive_rate = _safe_divide(fp, fp + tn)
    anomaly_detection_rate = recall
    f1 = _safe_divide(2 * precision * recall, precision + recall)
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "false_positive_rate": false_positive_rate,
        "anomaly_detection_rate": anomaly_detection_rate,
        "f1": f1,
    }


def _format_table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [len(header) for header in headers]
    for row in rows:
        for idx, cell in enumerate(row):
            widths[idx] = max(widths[idx], len(cell))

    border = "+-" + "-+-".join("-" * width for width in widths) + "-+"
    header_row = "| " + " | ".join(headers[idx].ljust(widths[idx]) for idx in range(len(headers))) + " |"
    lines = [border, header_row, border]
    for row in rows:
        lines.append("| " + " | ".join(row[idx].ljust(widths[idx]) for idx in range(len(headers))) + " |")
    lines.append(border)
    return "\n".join(lines)


def _parse_quantiles(raw: str | None) -> list[float]:
    if not raw:
        return [0.94, 0.95, 0.96, 0.97]
    values = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        quantile = float(token)
        if quantile <= 0.0 or quantile >= 1.0:
            raise ValueError
        values.append(quantile)
    if not values:
        raise ValueError
    return sorted(set(values))


def _build_time_splits(
    total_rows: int,
    *,
    repeats: int,
    test_size: int,
    min_train_size: int,
) -> list[tuple[int, int]]:
    if repeats <= 0:
        raise CommandError("--repeats must be at least 1.")
    if test_size <= 0:
        raise CommandError("--test-size must be at least 1.")
    if min_train_size <= 0:
        raise CommandError("--min-train-size must be at least 1.")
    if total_rows < min_train_size + test_size:
        raise CommandError(
            f"Not enough rows for time split. Need at least {min_train_size + test_size}, got {total_rows}."
        )

    max_repeats = (total_rows - min_train_size) // test_size
    if max_repeats < 1:
        raise CommandError("Unable to build any time split with current parameters.")
    actual_repeats = min(repeats, max_repeats)
    first_test_start = total_rows - (actual_repeats * test_size)
    if first_test_start < min_train_size:
        first_test_start = min_train_size

    splits: list[tuple[int, int]] = []
    for idx in range(actual_repeats):
        test_start = first_test_start + idx * test_size
        test_end = min(total_rows, test_start + test_size)
        if test_end <= test_start:
            continue
        if test_start < min_train_size:
            continue
        splits.append((test_start, test_end))
    if not splits:
        raise CommandError("No valid splits could be built.")
    return splits


class Command(BaseCommand):
    help = (
        "Evaluate Isolation Forest with rolling time-based splits and multiple score thresholds. "
        "Reports confusion matrix + precision/recall/FPR per threshold, and averaged metrics across repeats."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--contamination",
            type=float,
            default=0.08,
            help="Isolation Forest contamination value.",
        )
        parser.add_argument(
            "--threshold-quantiles",
            type=str,
            default="0.94,0.95,0.96,0.97",
            help="Comma-separated score quantiles for threshold calibration (0-1).",
        )
        parser.add_argument(
            "--repeats",
            type=int,
            default=5,
            help="Number of rolling time splits.",
        )
        parser.add_argument(
            "--test-size",
            type=int,
            default=100,
            help="Rows in each test window.",
        )
        parser.add_argument(
            "--min-train-size",
            type=int,
            default=300,
            help="Minimum train rows required before first test window.",
        )

    def handle(self, *args, **options):
        if np is None:
            raise CommandError("NumPy is required. Install dependencies from requirements.txt.")

        contamination = options["contamination"]
        if contamination <= 0.0 or contamination >= 0.5:
            raise CommandError("--contamination must be between 0 and 0.5.")
        try:
            quantiles = _parse_quantiles(options["threshold_quantiles"])
        except ValueError as exc:
            raise CommandError(
                "--threshold-quantiles must be comma-separated floats between 0 and 1 (exclusive)."
            ) from exc

        all_ids = list(
            AccessLog.objects.filter(is_simulated=True).order_by("accessed_at").values_list("id", flat=True)
        )
        if not all_ids:
            raise CommandError("No simulated logs found. Run generate_synthetic_logs first.")

        splits = _build_time_splits(
            len(all_ids),
            repeats=options["repeats"],
            test_size=options["test_size"],
            min_train_size=options["min_train_size"],
        )

        aggregate_rows: dict[str, list[dict[str, float]]] = defaultdict(list)
        detail_rows: list[list[str]] = []
        cumulative_exec_ms = 0.0

        for split_number, (test_start, test_end) in enumerate(splits, start=1):
            train_ids = all_ids[:test_start]
            test_ids = all_ids[test_start:test_end]
            train_queryset = AccessLog.objects.filter(id__in=train_ids).order_by("accessed_at")
            test_queryset = AccessLog.objects.filter(id__in=test_ids).order_by("accessed_at")

            scores = score_isolation_forest(
                train_queryset,
                test_queryset,
                contamination=contamination,
            )
            cumulative_exec_ms += scores.execution_time_ms

            label_map = dict(
                AccessLog.objects.filter(id__in=scores.test_ids).values_list("id", "is_true_anomaly")
            )
            y_true = np.array([bool(label_map.get(log_id, False)) for log_id in scores.test_ids], dtype=bool)

            model_default_pred = scores.test_predictions == -1
            model_default_metrics = _compute_metrics(y_true, model_default_pred)
            aggregate_rows["model_default"].append(model_default_metrics)
            detail_rows.append(
                [
                    str(split_number),
                    "model_default",
                    str(len(scores.test_ids)),
                    str(model_default_metrics["tp"]),
                    str(model_default_metrics["fp"]),
                    str(model_default_metrics["tn"]),
                    str(model_default_metrics["fn"]),
                    f"{model_default_metrics['precision']:.4f}",
                    f"{model_default_metrics['recall']:.4f}",
                    f"{model_default_metrics['false_positive_rate']:.4f}",
                    f"{model_default_metrics['f1']:.4f}",
                ]
            )

            for quantile in quantiles:
                threshold = float(np.quantile(scores.train_scores, quantile))
                y_pred = scores.test_scores >= threshold
                metrics = _compute_metrics(y_true, y_pred)
                key = f"q={quantile:.4f}"
                aggregate_rows[key].append(metrics)
                detail_rows.append(
                    [
                        str(split_number),
                        key,
                        str(len(scores.test_ids)),
                        str(metrics["tp"]),
                        str(metrics["fp"]),
                        str(metrics["tn"]),
                        str(metrics["fn"]),
                        f"{metrics['precision']:.4f}",
                        f"{metrics['recall']:.4f}",
                        f"{metrics['false_positive_rate']:.4f}",
                        f"{metrics['f1']:.4f}",
                    ]
                )

        self.stdout.write(self.style.SUCCESS("Time-split threshold evaluation complete."))
        self.stdout.write(
            f"Rows={len(all_ids)}, splits={len(splits)}, average model fit+score time={cumulative_exec_ms / len(splits):.2f} ms"
        )
        self.stdout.write("")
        self.stdout.write("Per-split results (confusion matrix + PR/FPR):")
        self.stdout.write(
            _format_table(
                [
                    "Split",
                    "Threshold",
                    "N",
                    "TP",
                    "FP",
                    "TN",
                    "FN",
                    "Precision",
                    "Recall",
                    "FPR",
                    "F1",
                ],
                detail_rows,
            )
        )

        average_rows: list[list[str]] = []
        for threshold_key in sorted(aggregate_rows.keys()):
            bucket = aggregate_rows[threshold_key]
            avg_precision = sum(row["precision"] for row in bucket) / len(bucket)
            avg_recall = sum(row["recall"] for row in bucket) / len(bucket)
            avg_fpr = sum(row["false_positive_rate"] for row in bucket) / len(bucket)
            avg_f1 = sum(row["f1"] for row in bucket) / len(bucket)
            avg_tp = sum(row["tp"] for row in bucket) / len(bucket)
            avg_fp = sum(row["fp"] for row in bucket) / len(bucket)
            avg_tn = sum(row["tn"] for row in bucket) / len(bucket)
            avg_fn = sum(row["fn"] for row in bucket) / len(bucket)
            average_rows.append(
                [
                    threshold_key,
                    f"{avg_precision:.4f}",
                    f"{avg_recall:.4f}",
                    f"{avg_fpr:.4f}",
                    f"{avg_f1:.4f}",
                    f"{avg_tp:.2f}",
                    f"{avg_fp:.2f}",
                    f"{avg_tn:.2f}",
                    f"{avg_fn:.2f}",
                ]
            )

        self.stdout.write("")
        self.stdout.write("Averaged metrics across splits:")
        self.stdout.write(
            _format_table(
                [
                    "Threshold",
                    "Avg Precision",
                    "Avg Recall",
                    "Avg FPR",
                    "Avg F1",
                    "Avg TP",
                    "Avg FP",
                    "Avg TN",
                    "Avg FN",
                ],
                average_rows,
            )
        )
