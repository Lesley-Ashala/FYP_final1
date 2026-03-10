# Hospital Record Access Monitoring System (Django + Isolation Forest)

This project is a lightweight hospital record monitoring system designed for low-resource environments.

It implements:
- Django authentication with role-based access (`admin`, `doctor`, `nurse`)
- Patient record module (CRUD)
- Automatic access logging for EHR interactions
- Isolation Forest anomaly detection
- Automated anomaly alerting
- Built-in evaluation metrics and tabular reporting

## 1) Setup

Recommended Python: **3.13.x** (Python 3.14 may fail building `scikit-learn` wheels on Windows).

```bash
py -3.13 -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
python manage.py migrate
```

## 2) Run

```bash
python manage.py runserver
```

Main URLs:
- HRMS login: `http://127.0.0.1:8000/hrms/login/`
- Admin monitor UI: `http://127.0.0.1:8000/hrms/admin-dashboard/`
- Legacy monitoring pages: `http://127.0.0.1:8000/patients/`, `http://127.0.0.1:8000/access-logs/`, `http://127.0.0.1:8000/anomalies/`, `http://127.0.0.1:8000/evaluations/`

Note about `db.sqlite3`:
- `db.sqlite3` is a binary SQLite database file, not a text file.
- Editors may show: "The file is not displayed in the text editor because it is either binary or uses an unsupported text encoding."
- This is expected. Use SQLite tools (`DB Browser for SQLite`, `sqlite3`) or Django admin/views to inspect data.

Seeded HRMS users (password: `Welcome@123`):
- `ADM-0192` (admin)
- `DOC-0458` (doctor)
- `NUR-1142` (nurse)

Synthetic-data users (password: `Hospital123!`):
- `admin_mike`, `doctor_amy`, `doctor_bob`, `doctor_lina`, `nurse_ella`, `nurse_omar`, `nurse_sara`

## 3) Generate Synthetic Dataset

Generate realistic logs in DB + CSV:

```bash
python manage.py generate_synthetic_logs --events 10000 --anomaly-rate 0.08 --days 30 --reset-simulated
```

CSV output:
- `data/hospital_access_logs.csv`

Examiner-friendly minimal dataset format:

```bash
python scripts/generate_exam_synthetic_dataset.py --records 10000 --anomaly-rate 0.10
```

Output:
- `data/synthetic_hospital_access_10000.csv`

## 4) Extract Behavioral Features (Objective iii)

```bash
python manage.py extract_access_features --last-hours 720 --output data/access_behavior_features.csv
```

Extracted features:
- `access_frequency_per_user`
- `time_of_day_access_deviation`
- `unique_patients_accessed`
- `role_based_access_deviation`

## 5) Run Anomaly Detection (Objective iv + automated alerts)

```bash
python manage.py run_anomaly_detection --contamination 0.08
```

What happens automatically:
- Isolation Forest is trained on access behavior features.
- Abnormal events are flagged (`is_flagged=True`).
- Risk score is assigned (`risk_score`).
- Severity is assigned (`low/medium/high/critical`).
- Alert state is created/opened (`alert_status=open`) for admin triage.

Periodic run:

```bash
python manage.py start_periodic_detection --interval-seconds 300 --window-hours 168
```

## 6) Evaluate Detection Performance (Objective vi)

```bash
python manage.py evaluate_detection --contamination 0.08 --autogenerate
```

Computed metrics:
- Precision
- Recall
- False Positive Rate
- Anomaly Detection Rate
- Execution Time (ms)

Evaluation table is printed in CLI and stored in DB for `/evaluations/`.

## 7) Objective-to-Implementation Mapping (Viva Defense)

### i) Authenticate hospital users through a secure login system
- Django auth-based login is enforced in HRMS (`monitoring/hrms_views.py`, `hrms_login` + `role_guard`).
- Role resolution from user profile (`monitoring/permissions.py`, `get_user_role`).
- Protected views require authenticated users and role checks.

### ii) Log all EHR access activities performed by authenticated users
- Access logging service: `monitoring/services.py`, `log_record_access`.
- Record-view/update/create/delete flows call `log_record_access`.
- Access logs stored in `AccessLog` table (`monitoring/models.py`).

### iii) Extract access behavior features from recorded access logs
- Feature engineering pipeline: `monitoring/services.py`, `build_feature_dataframe`.
- Optional CSV export command: `monitoring/management/commands/extract_access_features.py`.

### iv) Detect anomalous hospital record access patterns using Isolation Forest
- Isolation Forest pipeline: `monitoring/services.py`, `run_isolation_forest_detection`.
- CLI trigger: `run_anomaly_detection`.

### v) Present detected anomalous activities through an admin monitoring interface
- Alert/anomaly pages:
  - `/anomalies/` (legacy monitor)
  - `/hrms/alerts/` and `/hrms/investigations/` (admin workflow)
- RBAC limits these screens to admin.

### vi) Evaluate performance using precision, recall, false positive rate, anomaly detection rate, execution time
- Evaluation logic: `monitoring/services.py`, `evaluate_detector`.
- Evaluation command: `evaluate_detection`.
- UI table at `/evaluations/`.

## 7.1) Functional Requirements Coverage

- Access logging + log storage: `AccessLog` model + `log_record_access`.
- Data preparation + feature extraction: `build_feature_dataframe` and `extract_access_features`.
- Anomaly scoring (Isolation Forest): `run_isolation_forest_detection`.
- Flagging + alerts: `is_flagged`, `risk_score`, `alert_status`, automated alerts opened.
- Admin viewing: HRMS admin pages (`/hrms/admin-dashboard/`, `/hrms/alerts/`, `/hrms/investigations/`).
- Report export: audit log CSV export + investigation case report export.
- Plot anomaly score distribution: Admin dashboard includes histogram of `anomaly_score` values.

## 8) Core Files

- `monitoring/models.py` -> users/roles, patient records, access logs, detection runs, evaluation results
- `monitoring/services.py` -> logging, feature extraction, detection, alert automation, evaluation
- `monitoring/views.py` -> CRUD + monitoring pages + run actions
- `monitoring/hrms_views.py` -> role-based HRMS pages and admin alert workflow
- `monitoring/synthetic.py` -> synthetic dataset generation
- `monitoring/management/commands/` -> operational commands

## 9) View Table Relationships

Text relationship view:

```bash
python manage.py show_db_relationships
```

Mermaid ER relationship output:

```bash
python manage.py show_db_relationships --format mermaid
```
