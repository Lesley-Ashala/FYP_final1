from django.core.management.base import BaseCommand
from django.db import connection


class Command(BaseCommand):
    help = "Show database foreign-key relationships (text or Mermaid ER format)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--format",
            choices=["text", "mermaid"],
            default="text",
            help="Output format.",
        )
        parser.add_argument(
            "--include-django",
            action="store_true",
            help="Include all Django framework tables in the output.",
        )

    def handle(self, *args, **options):
        include_django = options["include_django"]
        with connection.cursor() as cursor:
            tables = sorted(connection.introspection.table_names(cursor))
            relationships: list[dict[str, str]] = []

            for table in tables:
                if not include_django and not (
                    table.startswith("monitoring_") or table == "auth_user"
                ):
                    continue
                constraints = connection.introspection.get_constraints(cursor, table)
                for name, details in constraints.items():
                    foreign_key = details.get("foreign_key")
                    if not foreign_key:
                        continue
                    referenced_table, referenced_column = foreign_key
                    columns = details.get("columns") or []
                    column_name = columns[0] if columns else ""
                    relationships.append(
                        {
                            "table": table,
                            "column": column_name,
                            "referenced_table": referenced_table,
                            "referenced_column": referenced_column,
                            "constraint_name": name,
                        }
                    )

        if not relationships:
            self.stdout.write(self.style.WARNING("No foreign-key relationships found."))
            return

        output_format = options["format"]
        if output_format == "mermaid":
            self.stdout.write("```mermaid")
            self.stdout.write("erDiagram")
            for rel in relationships:
                self.stdout.write(
                    f"    {rel['table'].upper()} }}o--|| {rel['referenced_table'].upper()} : "
                    f"\"{rel['column']} -> {rel['referenced_column']}\""
                )
            self.stdout.write("```")
            return

        table_width = max(len(r["table"]) for r in relationships)
        column_width = max(len(r["column"]) for r in relationships)
        ref_width = max(len(r["referenced_table"]) for r in relationships)
        ref_col_width = max(len(r["referenced_column"]) for r in relationships)

        header = (
            f"{'TABLE'.ljust(table_width)}  "
            f"{'COLUMN'.ljust(column_width)}  "
            f"{'REFERENCES_TABLE'.ljust(ref_width)}  "
            f"{'REFERENCES_COLUMN'.ljust(ref_col_width)}  "
            "CONSTRAINT"
        )
        self.stdout.write(header)
        self.stdout.write("-" * len(header))
        for rel in relationships:
            self.stdout.write(
                f"{rel['table'].ljust(table_width)}  "
                f"{rel['column'].ljust(column_width)}  "
                f"{rel['referenced_table'].ljust(ref_width)}  "
                f"{rel['referenced_column'].ljust(ref_col_width)}  "
                f"{rel['constraint_name']}"
            )
