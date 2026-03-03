# Hospital Record Access Monitoring (Django + Isolation Forest)

Lightweight Django application for hospital patient-record monitoring with:

- Role-based authentication (`doctor`, `nurse`, `admin`)
- Patient record CRUD
- Automatic record access logging
- Isolation Forest anomaly detection
- Built-in evaluation metrics on labeled synthetic anomalies
- SQLite default setup for low-resource environments

## 1) Project Setup

Recommended Python: **3.13.x** on Windows.
Python 3.14 often triggers source builds for `scikit-learn`/`scipy` and can fail.

```bash
py -3.13 -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
python manage.py migrate
```

## 2) Generate Synthetic Dataset

Creates demo users, patient records, access logs, and CSV export:

```bash
python manage.py generate_synthetic_logs --events 3000 --anomaly-rate 0.08 --days 30 --reset-simulated
```

CSV output: `data/hospital_access_logs.csv`

If you only need a standalone CSV without Django DB insertion:

```bash
python scripts/generate_dataset_csv.py --events 2000 --anomaly-rate 0.08 --days 30
```

Examiner-friendly minimal format (`user_id, role, access_time, patients_accessed, session_duration, label`):

```bash
python scripts/generate_exam_synthetic_dataset.py --records 10000 --anomaly-rate 0.10
```

Output: `data/synthetic_hospital_access_10000.csv`

## 3) Run the Web App

```bash
python manage.py runserver
```

Default landing page: `http://127.0.0.1:8000/` (redirects to HRMS login).
Legacy Django auth login page: `http://127.0.0.1:8000/accounts/login/`

## HRMS High-Fidelity UI Prototype (RBAC Frames)

Product-design prototype routes are available under:

- `http://127.0.0.1:8000/hrms/login/`
- `http://127.0.0.1:8000/hrms/otp/`
- `http://127.0.0.1:8000/hrms/admin-dashboard/`
- `http://127.0.0.1:8000/hrms/users/`
- `http://127.0.0.1:8000/hrms/roles-permissions/`
- `http://127.0.0.1:8000/hrms/system-settings/`
- `http://127.0.0.1:8000/hrms/nurse-dashboard/`
- `http://127.0.0.1:8000/hrms/patient-search/`
- `http://127.0.0.1:8000/hrms/patient-record/` (auto-selects first patient)
- `http://127.0.0.1:8000/hrms/patient-record/<patient_id>/`
- `http://127.0.0.1:8000/hrms/shift-handover/`
- `http://127.0.0.1:8000/hrms/audit-logs/`
- `http://127.0.0.1:8000/hrms/alerts/`
- `http://127.0.0.1:8000/hrms/investigations/`
- `http://127.0.0.1:8000/hrms/user-flow/`

On `hrms/login`, use:

- Demo password: `Welcome@123`
- Optional MFA OTP code: `482913`
- Roles: Super Admin, Records Admin, Nurse, Doctor/Clinician, Auditor, Security Officer

The prototype includes RBAC route guards, role-based action visibility, toasts, modals, empty/loading/error states, and security microcopy.

Most HRMS buttons are now backend-wired (create/disable/reset users, assign role, force MFA, save settings, save permissions with reason, patient access reason prompt, add vitals/notes, alert triage/closure, case notes/closure, audit CSV export based on role).

Seeded users (all password: `Hospital123!`):

- `doctor_amy` (doctor)
- `doctor_bob` (doctor)
- `doctor_lina` (doctor)
- `nurse_ella` (nurse)
- `nurse_omar` (nurse)
- `nurse_sara` (nurse)
- `admin_mike` (admin)

HRMS seeded staff (password: `Welcome@123`, auto-created on first HRMS load):

- `ADM-0192` (Super Admin)
- `REC-1034` (Records Admin)
- `NUR-1142` (Nurse)
- `DOC-0458` (Doctor/Clinician)
- `AUD-0083` (Auditor)
- `SEC-0217` (Security Officer)

## 4) Run Anomaly Detection

One-time run:

```bash
python manage.py run_anomaly_detection --contamination 0.08
```

Recent window only:

```bash
python manage.py run_anomaly_detection --last-hours 168
```

Periodic execution (no external cloud service required):

```bash
python manage.py start_periodic_detection --interval-seconds 300 --window-hours 168
```

## 5) Evaluate Model Performance

Runs detector against labeled synthetic anomalies and stores metrics:

```bash
python manage.py evaluate_detection --contamination 0.08 --autogenerate
```

Metrics computed:

- Precision
- Recall
- False Positive Rate
- Anomaly Detection Rate
- Execution Time

Results are printed in CLI table format and shown in the web UI (`/evaluations/`).

## Behavioral Features Used

Isolation Forest is trained on the following per-event features:

- `access_frequency_per_user`
- `time_of_day_access_deviation`
- `unique_patients_accessed`
- `role_based_access_deviation`

## Key Files

- `monitoring/models.py`: roles, patient records, access logs, detection/evaluation results
- `monitoring/views.py`: role-gated CRUD, anomaly/evaluation pages, trigger endpoints
- `monitoring/services.py`: feature extraction, Isolation Forest run, metric computation
- `monitoring/synthetic.py`: realistic synthetic dataset generation
- `monitoring/management/commands/`: dataset generation, detection, periodic runner, evaluation
