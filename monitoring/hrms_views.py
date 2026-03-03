from __future__ import annotations

import csv
import json
import random
from datetime import datetime
from functools import wraps
from io import StringIO

from django.contrib import messages
from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.db.models import Q
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_http_methods, require_POST

from monitoring.models import (
    AccessLog,
    AuditEvent,
    InvestigationCase,
    InvestigationCaseNote,
    NursingNote,
    NursingVital,
    PatientRecord,
    RoleChoices,
    SystemSetting,
    UserProfile,
)
from monitoring.permissions import get_user_role
from monitoring.services import log_record_access


User = get_user_model()

ROLE_CONFIG = {
    "admin": {
        "label": "Admin",
        "landing": "hrms-admin-dashboard",
        "can_export_audit": True,
    },
    "doctor": {
        "label": "Doctor",
        "landing": "hrms-nurse-dashboard",
        "can_export_audit": False,
    },
    "nurse": {
        "label": "Nurse",
        "landing": "hrms-nurse-dashboard",
        "can_export_audit": False,
    },
}

NAV_ITEMS = [
    {
        "label": "Admin Dashboard",
        "url_name": "hrms-admin-dashboard",
        "icon": "dashboard",
        "roles": {"admin"},
    },
    {
        "label": "Users",
        "url_name": "hrms-users",
        "icon": "users",
        "roles": {"admin"},
    },
    {
        "label": "Roles & Permissions",
        "url_name": "hrms-roles-permissions",
        "icon": "permissions",
        "roles": {"admin"},
    },
    {
        "label": "System Settings",
        "url_name": "hrms-system-settings",
        "icon": "settings",
        "roles": {"admin"},
    },
    {
        "label": "Clinical Dashboard",
        "url_name": "hrms-nurse-dashboard",
        "icon": "nurse",
        "roles": {"nurse", "doctor"},
    },
    {
        "label": "Patient Search",
        "url_name": "hrms-patient-search",
        "icon": "patients",
        "roles": {"nurse", "doctor"},
    },
    {
        "label": "Patient Record",
        "url_name": "hrms-patient-record-default",
        "icon": "records",
        "roles": {"nurse", "doctor"},
    },
    {
        "label": "Shift Handover",
        "url_name": "hrms-shift-handover",
        "icon": "handover",
        "roles": {"nurse"},
    },
    {
        "label": "Audit Logs",
        "url_name": "hrms-audit-logs",
        "icon": "audit",
        "roles": {"admin"},
    },
    {
        "label": "Alerts",
        "url_name": "hrms-alerts",
        "icon": "alerts",
        "roles": {"admin"},
    },
    {
        "label": "Investigations",
        "url_name": "hrms-investigations",
        "icon": "investigation",
        "roles": {"admin"},
    },
    {
        "label": "User Flow",
        "url_name": "hrms-user-flow",
        "icon": "flow",
        "roles": set(ROLE_CONFIG.keys()),
    },
]

DEFAULT_PERMISSION_MATRIX = {
    "admin": {
        "view_patient": True,
        "edit_patient": True,
        "add_vitals": True,
        "add_nursing_notes": True,
        "manage_users": True,
        "view_audit_log": True,
        "export_audit_log": True,
        "triage_alerts": True,
        "close_alerts": True,
    },
    "doctor": {
        "view_patient": True,
        "edit_patient": True,
        "add_vitals": True,
        "add_nursing_notes": True,
        "manage_users": False,
        "view_audit_log": False,
        "export_audit_log": False,
        "triage_alerts": False,
        "close_alerts": False,
    },
    "nurse": {
        "view_patient": True,
        "edit_patient": False,
        "add_vitals": True,
        "add_nursing_notes": True,
        "manage_users": False,
        "view_audit_log": False,
        "export_audit_log": False,
        "triage_alerts": False,
        "close_alerts": False,
    },
}


def _get_role(request: HttpRequest) -> str:
    role = request.session.get("hrms_demo_role", "admin")
    return role if role in ROLE_CONFIG else "admin"


def _has_demo_session(request: HttpRequest) -> bool:
    return "hrms_demo_role" in request.session


def _role_label(role: str) -> str:
    return ROLE_CONFIG.get(role, ROLE_CONFIG["admin"])["label"]


def _landing_for(role: str) -> str:
    return ROLE_CONFIG.get(role, ROLE_CONFIG["admin"])["landing"]


def _profile_role_to_demo(profile_role: str) -> str:
    mapping = {
        RoleChoices.ADMIN: "admin",
        RoleChoices.DOCTOR: "doctor",
        RoleChoices.NURSE: "nurse",
        "super_admin": "admin",
        "records_admin": "admin",
        "auditor": "admin",
        "security_officer": "admin",
        "doctor_clinician": "doctor",
    }
    return mapping.get(profile_role, "nurse")


def _demo_role_to_profile(demo_role: str) -> str:
    mapping = {
        "admin": RoleChoices.ADMIN,
        "doctor": RoleChoices.DOCTOR,
        "nurse": RoleChoices.NURSE,
    }
    return mapping.get(demo_role, RoleChoices.NURSE)


def _staff_id_to_username(staff_id: str) -> str:
    return staff_id.strip().lower().replace(" ", "_")


def _format_name(user: User) -> str:
    full_name = user.get_full_name().strip()
    return full_name if full_name else user.username


def _get_client_ip(request: HttpRequest) -> str | None:
    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def _actor_user(request: HttpRequest) -> User | None:
    actor_id = request.session.get("hrms_actor_user_id")
    if actor_id:
        return User.objects.filter(id=actor_id).first()
    return None


def _actor_or_fallback_user(request: HttpRequest) -> User:
    actor = _actor_user(request)
    if actor:
        return actor
    fallback = (
        User.objects.filter(is_superuser=True).first()
        or User.objects.order_by("id").first()
    )
    if fallback:
        return fallback
    user = User.objects.create_user(
        username="system_operator",
        email="system.operator@hospital.local",
        password="Welcome@123",
        first_name="System",
        last_name="Operator",
    )
    UserProfile.objects.update_or_create(
        user=user,
        defaults={"role": RoleChoices.ADMIN, "department": "Health IT"},
    )
    return user


def _log_audit_event(
    request: HttpRequest,
    *,
    action_type: str,
    outcome: str = AuditEvent.Outcome.SUCCESS,
    patient_ref: str = "",
    target_ref: str = "",
    details: str = "",
) -> None:
    actor = _actor_user(request)
    department = ""
    if actor and hasattr(actor, "profile"):
        department = actor.profile.department
    AuditEvent.objects.create(
        user=actor,
        department=department,
        patient_ref=patient_ref[:30],
        action_type=action_type[:60],
        target_ref=target_ref[:100],
        details=details[:255],
        outcome=outcome,
        ip_address=_get_client_ip(request),
        device=request.META.get("HTTP_USER_AGENT", "")[:120],
    )


def _ensure_session_from_authenticated_user(request: HttpRequest) -> None:
    if _has_demo_session(request):
        return
    if not request.user or not request.user.is_authenticated:
        return
    role = _profile_role_to_demo(get_user_role(request.user))
    request.session["hrms_demo_role"] = role
    request.session["hrms_actor_user_id"] = request.user.id
    request.session["hrms_demo_user"] = f"{request.user.username} / {_role_label(role)} User"


def _ensure_seed_data() -> None:
    seed_users = [
        ("ADM-0192", "Morgan", "Blake", "morgan.blake@hospital.local", "admin", "Health IT"),
        ("NUR-1142", "Clara", "Moreno", "clara.moreno@hospital.local", "nurse", "Ward C"),
        ("DOC-0458", "Arjun", "Patel", "arjun.patel@hospital.local", "doctor", "Cardiology"),
    ]
    for staff_id, first, last, email, demo_role, department in seed_users:
        username = _staff_id_to_username(staff_id)
        user, created = User.objects.get_or_create(
            username=username,
            defaults={
                "first_name": first,
                "last_name": last,
                "email": email,
                "is_staff": demo_role == "admin",
                "is_superuser": demo_role == "admin",
            },
        )
        changed_fields = []
        if user.first_name != first:
            user.first_name = first
            changed_fields.append("first_name")
        if user.last_name != last:
            user.last_name = last
            changed_fields.append("last_name")
        if user.email != email:
            user.email = email
            changed_fields.append("email")
        if not user.is_active:
            user.is_active = True
            changed_fields.append("is_active")
        expected_staff = demo_role == "admin"
        if user.is_staff != expected_staff:
            user.is_staff = expected_staff
            changed_fields.append("is_staff")
        if user.is_superuser != expected_staff:
            user.is_superuser = expected_staff
            changed_fields.append("is_superuser")
        if changed_fields:
            user.save(update_fields=changed_fields)
        if created or not user.check_password("Welcome@123"):
            user.set_password("Welcome@123")
            user.save(update_fields=["password"])

        profile, _ = UserProfile.objects.get_or_create(user=user)
        profile.role = _demo_role_to_profile(demo_role)
        profile.department = department
        profile.mfa_enabled = True
        profile.save(update_fields=["role", "department", "mfa_enabled"])

    clinician = User.objects.filter(username=_staff_id_to_username("DOC-0458")).first()
    patient_seed = [
        ("PAT-000342", "Avery Cole", "1969-03-15", "Post-operative recovery", "Allergy: Penicillin"),
        ("PAT-000501", "Jordan Hayes", "1958-09-22", "Respiratory observation", "SpO2 monitoring"),
        ("PAT-000581", "Casey Lin", "1981-01-04", "Pain management review", "Follow-up required"),
    ]
    for hospital_id, name, dob_str, diagnosis, notes in patient_seed:
        PatientRecord.objects.get_or_create(
            hospital_id=hospital_id,
            defaults={
                "full_name": name,
                "date_of_birth": datetime.strptime(dob_str, "%Y-%m-%d").date(),
                "diagnosis": diagnosis,
                "notes": notes,
                "attending_doctor": clinician,
            },
        )

    if not AccessLog.objects.filter(is_flagged=True).exists():
        nurse = User.objects.filter(username=_staff_id_to_username("NUR-1142")).first()
        doctor = User.objects.filter(username=_staff_id_to_username("DOC-0458")).first()
        patient_342 = PatientRecord.objects.filter(hospital_id="PAT-000342").first()
        patient_501 = PatientRecord.objects.filter(hospital_id="PAT-000501").first()
        sample_alerts = [
            (
                nurse,
                patient_342,
                AccessLog.AlertSeverity.CRITICAL,
                96.0,
                "Bulk record export from shared workstation outside shift hours",
            ),
            (
                nurse,
                patient_501,
                AccessLog.AlertSeverity.HIGH,
                82.0,
                "Access burst: 36 records in 11 minutes by NUR-1142",
            ),
            (
                doctor,
                patient_501,
                AccessLog.AlertSeverity.MEDIUM,
                61.0,
                "Repeated off-pattern access to non-assigned patient records",
            ),
        ]
        for user, patient, severity, risk_score, summary in sample_alerts:
            if not user or not patient:
                continue
            AccessLog.objects.create(
                user=user,
                role_snapshot=user.profile.role if hasattr(user, "profile") else RoleChoices.NURSE,
                patient_record=patient,
                action=AccessLog.AccessAction.VIEW,
                is_flagged=True,
                anomaly_score=risk_score / 100.0,
                risk_score=risk_score,
                alert_severity=severity,
                alert_status=AccessLog.AlertStatus.OPEN,
                notes=summary[:255],
            )

    case, _ = InvestigationCase.objects.get_or_create(
        case_reference="CASE-2026-014",
        defaults={
            "title": "Unauthorized after-hours access pattern investigation",
            "summary": "Linked anomalies from Ward C access bursts and export attempts.",
            "status": InvestigationCase.CaseStatus.IN_REVIEW,
            "owner": User.objects.filter(username=_staff_id_to_username("ADM-0192")).first(),
            "opened_by": User.objects.filter(username=_staff_id_to_username("ADM-0192")).first(),
        },
    )
    AccessLog.objects.filter(is_flagged=True, case_reference="").update(case_reference=case.case_reference)

    defaults = {
        "password_min_length": "12",
        "password_rotation_days": "90",
        "session_timeout_minutes": "10",
        "mfa_policy": "required_privileged",
        "audit_retention_years": "7",
        "audit_export_format": "csv_hash_manifest",
        "permissions_matrix": json.dumps(DEFAULT_PERMISSION_MATRIX),
    }
    for key, value in defaults.items():
        SystemSetting.objects.get_or_create(key=key, defaults={"value": value})


def _build_context(request: HttpRequest, *, page_title: str, page_name: str, page_note: str = "") -> dict:
    role = _get_role(request)
    active_url_name = request.resolver_match.url_name if request.resolver_match else ""
    nav = [item for item in NAV_ITEMS if role in item["roles"]]
    return {
        "brand_name": "Hospital Secure Records",
        "page_title": page_title,
        "page_name": page_name,
        "page_note": page_note,
        "demo_role": role,
        "demo_role_label": _role_label(role),
        "demo_user": request.session.get("hrms_demo_user", "ADM-0192 / Morgan Blake"),
        "session_expiry": "10 minutes",
        "nav_items": nav,
        "active_url_name": active_url_name,
        "can_export_audit": ROLE_CONFIG[role]["can_export_audit"],
    }


def _access_denied_response(request: HttpRequest, allowed_roles: tuple[str, ...]) -> HttpResponse:
    context = _build_context(
        request,
        page_title="Access Denied",
        page_name="Access denied",
        page_note="RBAC route guard blocked this page.",
    )
    context["required_roles"] = [_role_label(role) for role in allowed_roles]
    _log_audit_event(
        request,
        action_type="rbac_access_denied",
        outcome=AuditEvent.Outcome.DENIED,
        details=f"Required roles: {', '.join(context['required_roles'])}",
    )
    return render(request, "hrms/access_denied.html", context, status=403)


def role_guard(*allowed_roles: str):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(request: HttpRequest, *args, **kwargs):
            _ensure_seed_data()
            _ensure_session_from_authenticated_user(request)
            if not _has_demo_session(request):
                return redirect("hrms-login")
            if _get_role(request) not in allowed_roles:
                return _access_denied_response(request, allowed_roles)
            return view_func(request, *args, **kwargs)

        return wrapped

    return decorator


def _parse_date(value: str | None):
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        return None


def _filter_audit_events(request: HttpRequest):
    queryset = AuditEvent.objects.select_related("user").all()
    date_from = _parse_date(request.GET.get("date_from"))
    date_to = _parse_date(request.GET.get("date_to"))
    user_query = request.GET.get("user", "").strip()
    department = request.GET.get("department", "").strip()
    patient_ref = request.GET.get("patient_ref", "").strip()
    action_type = request.GET.get("action_type", "").strip()

    if date_from:
        queryset = queryset.filter(timestamp__date__gte=date_from)
    if date_to:
        queryset = queryset.filter(timestamp__date__lte=date_to)
    if user_query:
        queryset = queryset.filter(
            Q(user__username__icontains=user_query)
            | Q(user__first_name__icontains=user_query)
            | Q(user__last_name__icontains=user_query)
        )
    if department:
        queryset = queryset.filter(department__icontains=department)
    if patient_ref:
        queryset = queryset.filter(patient_ref__icontains=patient_ref)
    if action_type:
        queryset = queryset.filter(action_type__icontains=action_type)
    return queryset


@require_http_methods(["GET", "POST"])
def hrms_login(request: HttpRequest) -> HttpResponse:
    _ensure_seed_data()
    error = ""

    if request.method == "POST":
        staff = request.POST.get("staff_id", "").strip()
        password = request.POST.get("password", "")

        if not staff:
            error = "Please enter Staff ID or email."
        elif staff.upper() == "LOCKED-991":
            error = "Account locked after repeated failed sign-in attempts."
        else:
            actor = User.objects.filter(
                Q(username__iexact=_staff_id_to_username(staff))
                | Q(email__iexact=staff)
            ).first()
            if actor:
                if not actor.check_password(password):
                    error = "Incorrect password. You have 2 attempts remaining."
                elif not actor.is_active:
                    error = "Account is disabled. Contact Records Administration."
                else:
                    role = _profile_role_to_demo(get_user_role(actor))
                    request.session["hrms_actor_user_id"] = actor.id
                    request.session["hrms_demo_role"] = role
                    request.session["hrms_demo_user"] = f"{actor.username.upper()} / {_format_name(actor)}"
                    _log_audit_event(
                        request,
                        action_type="login_success",
                        details=f"Role resolved as {role}",
                    )
                    return redirect(_landing_for(role))
            elif password == "Welcome@123":
                inferred_role = "nurse"
                staff_upper = staff.upper()
                if staff_upper.startswith("ADM"):
                    inferred_role = "admin"
                elif staff_upper.startswith("DOC"):
                    inferred_role = "doctor"
                request.session["hrms_demo_role"] = inferred_role
                request.session["hrms_demo_user"] = f"{staff_upper} / {_role_label(inferred_role)} User"
                request.session["hrms_actor_user_id"] = None
                _log_audit_event(
                    request,
                    action_type="login_success_demo",
                    details=f"Demo login for {staff} as {inferred_role}",
                )
                return redirect(_landing_for(inferred_role))
            else:
                error = "Incorrect password. You have 2 attempts remaining."
                _log_audit_event(
                    request,
                    action_type="login_failed",
                    outcome=AuditEvent.Outcome.DENIED,
                    details=f"Failed login attempt for {staff}",
                )

    context = {
        "brand_name": "Hospital Secure Records",
        "error": error,
    }
    return render(request, "hrms/login.html", context)


def hrms_root(request: HttpRequest) -> HttpResponse:
    _ensure_seed_data()
    _ensure_session_from_authenticated_user(request)
    if "hrms_demo_role" not in request.session:
        return redirect("hrms-login")
    return redirect(_landing_for(_get_role(request)))


def hrms_logout(request: HttpRequest) -> HttpResponse:
    _log_audit_event(request, action_type="logout")
    for key in ("hrms_demo_role", "hrms_demo_user", "hrms_actor_user_id"):
        if key in request.session:
            del request.session[key]
    return redirect("hrms-login")


@role_guard("admin")
def admin_dashboard(request: HttpRequest) -> HttpResponse:
    today = timezone.now().date()
    active_sessions = Session.objects.filter(expire_date__gte=timezone.now()).count()
    flagged_open = AccessLog.objects.filter(is_flagged=True, alert_status=AccessLog.AlertStatus.OPEN).count()
    context = _build_context(
        request,
        page_title="Admin Dashboard",
        page_name="Admin Dashboard",
        page_note="Operational and security overview for the records platform.",
    )
    context["kpis"] = [
        {"label": "Total users", "value": f"{User.objects.count()}", "trend": "Managed identities in tenant"},
        {"label": "Active sessions", "value": f"{active_sessions}", "trend": "Includes MFA-verified sessions"},
        {
            "label": "Records accessed today",
            "value": f"{AccessLog.objects.filter(accessed_at__date=today).count()}",
            "trend": "Patient and admin actions combined",
        },
        {"label": "Flagged access events", "value": f"{flagged_open}", "trend": "Open security alerts pending triage"},
    ]

    recent_alert_logs = AccessLog.objects.filter(is_flagged=True).order_by("-accessed_at")[:5]
    context["recent_alerts"] = [
        {
            "id": f"ALT-{log.id:05d}",
            "severity": (log.alert_severity or AccessLog.AlertSeverity.MEDIUM).title(),
            "summary": log.notes or "Behavioral anomaly detected",
            "owner": _format_name(log.assigned_investigator) if log.assigned_investigator else "Pending assignment",
        }
        for log in recent_alert_logs
    ]
    return render(request, "hrms/admin_dashboard.html", context)


@role_guard("admin")
def users_page(request: HttpRequest) -> HttpResponse:
    context = _build_context(
        request,
        page_title="User Management",
        page_name="Users",
        page_note="Manage staff accounts, role assignments, and authentication controls.",
    )
    queryset = User.objects.select_related("profile").order_by("username")
    context["users"] = [
        {
            "id": user.id,
            "name": _format_name(user),
            "staff_id": user.username.upper(),
            "role": _role_label(_profile_role_to_demo(user.profile.role if hasattr(user, "profile") else RoleChoices.NURSE)),
            "role_key": _profile_role_to_demo(user.profile.role if hasattr(user, "profile") else RoleChoices.NURSE),
            "department": user.profile.department if hasattr(user, "profile") else "",
            "status": "Active" if user.is_active else "Suspended",
            "last_login": user.last_login.strftime("%Y-%m-%d %H:%M") if user.last_login else "-",
            "mfa": "Enabled" if getattr(user.profile, "mfa_enabled", False) else "Disabled",
        }
        for user in queryset
    ]
    context["roles_for_assignment"] = [{"key": key, "label": cfg["label"]} for key, cfg in ROLE_CONFIG.items()]
    return render(request, "hrms/users.html", context)


@role_guard("admin")
@require_POST
def create_user_action(request: HttpRequest) -> HttpResponse:
    full_name = request.POST.get("full_name", "").strip()
    staff_id = request.POST.get("staff_id", "").strip()
    email = request.POST.get("email", "").strip()
    demo_role = request.POST.get("role", "nurse")
    department = request.POST.get("department", "").strip()
    status = request.POST.get("status", "active")

    if not full_name or not staff_id:
        messages.error(request, "Full name and Staff ID are required.")
        return redirect("hrms-users")

    username = _staff_id_to_username(staff_id)
    if User.objects.filter(username=username).exists():
        messages.error(request, f"Staff ID {staff_id} already exists.")
        return redirect("hrms-users")

    first_name, _, last_name = full_name.partition(" ")
    user = User.objects.create(
        username=username,
        first_name=first_name,
        last_name=last_name,
        email=email,
        is_active=(status == "active"),
        is_staff=demo_role == "admin",
    )
    user.set_password("TempPass@123")
    user.save(update_fields=["password"])

    profile, _ = UserProfile.objects.get_or_create(user=user)
    profile.role = _demo_role_to_profile(demo_role)
    profile.department = department
    profile.mfa_enabled = True
    profile.force_password_reset = True
    profile.save()

    _log_audit_event(
        request,
        action_type="create_user",
        target_ref=username,
        details=f"Role={demo_role}, Department={department}",
    )
    messages.success(request, f"User {staff_id} created. Temporary password: TempPass@123")
    return redirect("hrms-users")


@role_guard("admin")
@require_POST
def disable_user_action(request: HttpRequest, user_id: int) -> HttpResponse:
    target = get_object_or_404(User, id=user_id)
    reason = request.POST.get("reason", "").strip()
    target.is_active = False
    target.save(update_fields=["is_active"])

    _log_audit_event(
        request,
        action_type="disable_user",
        target_ref=target.username,
        details=reason or "No reason provided",
    )
    messages.success(request, f"User {target.username.upper()} disabled.")
    return redirect("hrms-users")


@role_guard("admin")
@require_POST
def reset_password_action(request: HttpRequest, user_id: int) -> HttpResponse:
    target = get_object_or_404(User, id=user_id)
    temp_password = f"Reset@{random.randint(1000, 9999)}"
    target.set_password(temp_password)
    target.save(update_fields=["password"])
    profile, _ = UserProfile.objects.get_or_create(user=target)
    profile.force_password_reset = True
    profile.save(update_fields=["force_password_reset"])

    _log_audit_event(
        request,
        action_type="reset_password",
        target_ref=target.username,
        details="Temporary password generated",
    )
    messages.success(request, f"Temporary password for {target.username.upper()}: {temp_password}")
    return redirect("hrms-users")


@role_guard("admin")
@require_POST
def force_mfa_action(request: HttpRequest) -> HttpResponse:
    UserProfile.objects.update(mfa_enabled=True)
    _log_audit_event(request, action_type="force_mfa", details="MFA enforced for all user profiles")
    messages.success(request, "MFA policy pushed to all users.")
    return redirect("hrms-users")


@role_guard("admin")
@require_POST
def assign_role_action(request: HttpRequest, user_id: int) -> HttpResponse:
    target = get_object_or_404(User, id=user_id)
    demo_role = request.POST.get("role", "nurse")
    if demo_role not in ROLE_CONFIG:
        messages.error(request, "Invalid role selection.")
        return redirect("hrms-users")

    profile, _ = UserProfile.objects.get_or_create(user=target)
    profile.role = _demo_role_to_profile(demo_role)
    profile.save(update_fields=["role"])
    _log_audit_event(
        request,
        action_type="assign_role",
        target_ref=target.username,
        details=f"Assigned role {demo_role}",
    )
    messages.success(request, f"Role updated for {target.username.upper()}.")
    return redirect("hrms-users")


@role_guard("admin")
def roles_permissions_page(request: HttpRequest) -> HttpResponse:
    context = _build_context(
        request,
        page_title="Roles & Permissions",
        page_name="Roles & Permissions",
        page_note="Any permission change requires a reason and is recorded in audit logs.",
    )

    matrix_setting = SystemSetting.objects.filter(key="permissions_matrix").first()
    matrix = DEFAULT_PERMISSION_MATRIX
    if matrix_setting:
        try:
            matrix = json.loads(matrix_setting.value)
        except json.JSONDecodeError:
            matrix = DEFAULT_PERMISSION_MATRIX

    headers = [
        ("view_patient", "View Patient"),
        ("edit_patient", "Edit Patient"),
        ("add_vitals", "Add Vitals"),
        ("add_nursing_notes", "Add Nursing Notes"),
        ("manage_users", "Manage Users"),
        ("view_audit_log", "View Audit Log"),
        ("export_audit_log", "Export Audit Log"),
        ("triage_alerts", "Triage Alerts"),
        ("close_alerts", "Close Alerts"),
    ]
    rows = []
    for role_key in ["admin", "doctor", "nurse"]:
        role_values = matrix.get(role_key, {})
        row_permissions = [(perm_key, bool(role_values.get(perm_key, False))) for perm_key, _ in headers]
        rows.append((ROLE_CONFIG[role_key]["label"], role_key, row_permissions))

    context["permission_headers"] = [label for _, label in headers]
    context["permission_columns"] = headers
    context["permission_rows"] = rows
    return render(request, "hrms/roles_permissions.html", context)


@role_guard("admin")
@require_POST
def save_permissions_action(request: HttpRequest) -> HttpResponse:
    reason = request.POST.get("change_reason", "").strip()
    if not reason:
        messages.error(request, "Reason for change is required.")
        return redirect("hrms-roles-permissions")

    updated_matrix = {}
    for role_key in ROLE_CONFIG.keys():
        updated_matrix[role_key] = {}
        for perm_key in DEFAULT_PERMISSION_MATRIX["admin"].keys():
            input_name = f"perm__{role_key}__{perm_key}"
            updated_matrix[role_key][perm_key] = bool(request.POST.get(input_name))

    SystemSetting.objects.update_or_create(
        key="permissions_matrix",
        defaults={
            "value": json.dumps(updated_matrix),
            "updated_by": _actor_user(request),
        },
    )
    _log_audit_event(
        request,
        action_type="update_permissions",
        details=f"Reason: {reason}",
    )
    messages.success(request, "Role and permission matrix updated.")
    return redirect("hrms-roles-permissions")


def _setting_value(key: str, default: str) -> str:
    setting = SystemSetting.objects.filter(key=key).first()
    return setting.value if setting else default


@role_guard("admin")
def system_settings_page(request: HttpRequest) -> HttpResponse:
    context = _build_context(
        request,
        page_title="System Settings",
        page_name="System Settings",
        page_note="Authentication policy, retention controls, and export governance.",
    )
    context["settings"] = {
        "password_min_length": _setting_value("password_min_length", "12"),
        "password_rotation_days": _setting_value("password_rotation_days", "90"),
        "session_timeout_minutes": _setting_value("session_timeout_minutes", "10"),
        "mfa_policy": _setting_value("mfa_policy", "required_privileged"),
        "audit_retention_years": _setting_value("audit_retention_years", "7"),
        "audit_export_format": _setting_value("audit_export_format", "csv_hash_manifest"),
        "require_complex_password": _setting_value("require_complex_password", "true"),
        "step_up_export_mfa": _setting_value("step_up_export_mfa", "true"),
        "allow_trusted_device_bypass": _setting_value("allow_trusted_device_bypass", "false"),
        "require_export_reason": _setting_value("require_export_reason", "true"),
    }
    return render(request, "hrms/system_settings.html", context)


@role_guard("admin")
@require_POST
def save_system_settings_action(request: HttpRequest) -> HttpResponse:
    actor = _actor_user(request)
    key_values = {
        "password_min_length": request.POST.get("password_min_length", "12"),
        "password_rotation_days": request.POST.get("password_rotation_days", "90"),
        "session_timeout_minutes": request.POST.get("session_timeout_minutes", "10"),
        "mfa_policy": request.POST.get("mfa_policy", "required_privileged"),
        "audit_retention_years": request.POST.get("audit_retention_years", "7"),
        "audit_export_format": request.POST.get("audit_export_format", "csv_hash_manifest"),
        "require_complex_password": "true" if request.POST.get("require_complex_password") else "false",
        "step_up_export_mfa": "true" if request.POST.get("step_up_export_mfa") else "false",
        "allow_trusted_device_bypass": "true" if request.POST.get("allow_trusted_device_bypass") else "false",
        "require_export_reason": "true" if request.POST.get("require_export_reason") else "false",
    }
    for key, value in key_values.items():
        SystemSetting.objects.update_or_create(
            key=key,
            defaults={"value": value, "updated_by": actor},
        )

    _log_audit_event(request, action_type="update_system_settings", details="System settings updated")
    messages.success(request, "System settings saved successfully.")
    return redirect("hrms-system-settings")


def _patient_meta(patient: PatientRecord) -> dict:
    score = sum(ord(ch) for ch in patient.hospital_id)
    wards = ["Ward C", "ICU-2", "Ward A", "Ward B"]
    statuses = ["Stable", "Observation", "Needs review"]
    genders = ["F", "M"]
    ward = wards[score % len(wards)]
    bed = f"Bed {score % 20 + 1:02d}"
    age = max(1, int((timezone.now().date() - patient.date_of_birth).days / 365.25))
    clinician = _format_name(patient.attending_doctor) if patient.attending_doctor else "Unassigned"
    return {
        "patient_ref": patient.hospital_id,
        "name": patient.full_name,
        "ward": ward,
        "bed": bed,
        "age": age,
        "gender": genders[score % len(genders)],
        "status": statuses[score % len(statuses)],
        "clinician": clinician,
        "pk": patient.pk,
    }


@role_guard("nurse", "doctor")
def nurse_dashboard(request: HttpRequest) -> HttpResponse:
    actor = _actor_user(request)
    today = timezone.now().date()
    assigned_qs = PatientRecord.objects.all()
    if actor and _get_role(request) == "doctor":
        assigned_qs = assigned_qs.filter(attending_doctor=actor)

    assigned_patients = list(assigned_qs[:20])
    assigned_ids = [patient.id for patient in assigned_patients]
    today_vitals = NursingVital.objects.filter(
        patient_record_id__in=assigned_ids,
        recorded_at__date=today,
    ).count()
    pending_notes = max(0, len(assigned_patients) - NursingNote.objects.filter(
        patient_record_id__in=assigned_ids,
        created_at__date=today,
    ).values("patient_record_id").distinct().count())

    context = _build_context(
        request,
        page_title="Nurse Dashboard",
        page_name="Nurse Dashboard",
        page_note="Assigned patient workload, due tasks, and clinical alerts.",
    )
    context["kpis"] = [
        {"label": "Assigned patients today", "value": str(len(assigned_patients)), "trend": "Current active assignment"},
        {"label": "Tasks due", "value": str(max(1, pending_notes + 2)), "trend": "Includes vitals and notes"},
        {"label": "Recent vitals recorded", "value": str(today_vitals), "trend": "Current shift entries"},
        {"label": "Pending notes", "value": str(pending_notes), "trend": "Needs completion before handover"},
    ]
    context["notifications"] = [
        {"type": "assignment", "message": "New assignment available in Ward C."},
        {"type": "due", "message": "Record due: follow-up vitals pending for one patient."},
        {"type": "alert", "message": "Alert: abnormal vitals trend identified in ICU-2."},
    ]
    context["assigned_patients"] = [_patient_meta(patient) for patient in assigned_patients[:8]]
    return render(request, "hrms/nurse_dashboard.html", context)


@role_guard("nurse", "doctor")
def patient_search_page(request: HttpRequest) -> HttpResponse:
    context = _build_context(
        request,
        page_title="Patient Search",
        page_name="Patient Search & Results",
        page_note="Access reason is required before opening any patient record.",
    )
    patient_number = request.GET.get("patient_number", "").strip()
    patient_name = request.GET.get("patient_name", "").strip()
    ward_filter = request.GET.get("ward", "").strip()
    bed_filter = request.GET.get("bed", "").strip()
    status_filter = request.GET.get("status", "").strip()

    queryset = PatientRecord.objects.select_related("attending_doctor").all()
    if patient_number:
        queryset = queryset.filter(hospital_id__icontains=patient_number)
    if patient_name:
        queryset = queryset.filter(full_name__icontains=patient_name)

    cards = [_patient_meta(patient) for patient in queryset[:80]]
    if ward_filter and ward_filter != "Any":
        cards = [row for row in cards if row["ward"] == ward_filter]
    if bed_filter:
        cards = [row for row in cards if bed_filter.lower() in row["bed"].lower()]
    if status_filter and status_filter != "Any":
        cards = [row for row in cards if row["status"] == status_filter]

    context["patients"] = cards
    context["filters"] = {
        "patient_number": patient_number,
        "patient_name": patient_name,
        "ward": ward_filter or "Any",
        "bed": bed_filter,
        "status": status_filter or "Any",
    }
    return render(request, "hrms/patient_search.html", context)


@role_guard("nurse", "doctor")
@require_POST
def open_patient_record_action(request: HttpRequest, patient_id: int) -> HttpResponse:
    patient = get_object_or_404(PatientRecord, id=patient_id)
    reason = request.POST.get("access_reason", "").strip()
    note = request.POST.get("access_note", "").strip()
    if not reason:
        messages.error(request, "Access reason is required before opening a record.")
        return redirect("hrms-patient-search")

    actor = _actor_or_fallback_user(request)
    log_record_access(
        user=actor,
        patient_record=patient,
        action=AccessLog.AccessAction.VIEW,
        request=request,
        notes=f"Access reason: {reason}. {note}"[:255],
    )
    _log_audit_event(
        request,
        action_type="open_patient_record",
        patient_ref=patient.hospital_id,
        details=f"Reason={reason}",
    )
    request.session["hrms_last_access_reason"] = reason
    messages.success(request, f"Access reason recorded for {patient.hospital_id}.")
    return redirect("hrms-patient-record", pk=patient.id)


@role_guard("nurse", "doctor")
def patient_record_default_redirect(request: HttpRequest) -> HttpResponse:
    patient = PatientRecord.objects.order_by("hospital_id").first()
    if not patient:
        messages.error(request, "No patient records found. Create a patient record first.")
        return redirect("hrms-patient-search")
    return redirect("hrms-patient-record", pk=patient.id)


@role_guard("nurse", "doctor")
def patient_record_page(request: HttpRequest, pk: int) -> HttpResponse:
    patient = get_object_or_404(PatientRecord.objects.select_related("attending_doctor"), id=pk)
    context = _build_context(
        request,
        page_title="Patient Record",
        page_name="Patient Record",
        page_note="Nurse-facing chart with focused inputs for vitals and nursing notes.",
    )
    context["patient"] = patient
    context["patient_meta"] = _patient_meta(patient)
    context["recent_vitals"] = NursingVital.objects.filter(patient_record=patient)[:5]
    context["recent_notes"] = NursingNote.objects.filter(patient_record=patient)[:5]
    context["last_access_reason"] = request.session.get("hrms_last_access_reason", "")
    return render(request, "hrms/patient_record.html", context)


def _to_int(value: str, field: str):
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ValueError(f"Invalid value for {field}.")


@role_guard("nurse", "doctor")
@require_POST
def add_vitals_action(request: HttpRequest, pk: int) -> HttpResponse:
    patient = get_object_or_404(PatientRecord, id=pk)
    try:
        temperature = float(request.POST.get("temperature_c", ""))
        pulse = _to_int(request.POST.get("pulse_bpm", ""), "pulse")
        respiration = _to_int(request.POST.get("respiration_rate", ""), "respiration")
        oxygen = _to_int(request.POST.get("oxygen_saturation", ""), "oxygen saturation")
    except ValueError as exc:
        messages.error(request, str(exc))
        return redirect("hrms-patient-record", pk=pk)

    actor = _actor_or_fallback_user(request)
    NursingVital.objects.create(
        patient_record=patient,
        recorded_by=actor,
        blood_pressure=request.POST.get("blood_pressure", "").strip() or "N/A",
        temperature_c=temperature,
        pulse_bpm=pulse,
        respiration_rate=respiration,
        oxygen_saturation=oxygen,
        notes=request.POST.get("vitals_notes", "").strip(),
    )
    log_record_access(
        user=actor,
        patient_record=patient,
        action=AccessLog.AccessAction.UPDATE,
        request=request,
        notes="Vitals updated",
    )
    _log_audit_event(
        request,
        action_type="add_vitals",
        patient_ref=patient.hospital_id,
        details="Vitals entry created",
    )
    messages.success(request, "Vitals saved successfully.")
    return redirect("hrms-patient-record", pk=pk)


@role_guard("nurse", "doctor")
@require_POST
def add_nursing_note_action(request: HttpRequest, pk: int) -> HttpResponse:
    patient = get_object_or_404(PatientRecord, id=pk)
    note_text = request.POST.get("note_text", "").strip()
    if not note_text:
        messages.error(request, "Nursing note text is required.")
        return redirect("hrms-patient-record", pk=pk)

    pain_score_value = request.POST.get("pain_score", "").strip()
    pain_score = None
    if pain_score_value:
        try:
            pain_score = int(pain_score_value)
        except ValueError:
            messages.error(request, "Pain score must be a number from 0 to 10.")
            return redirect("hrms-patient-record", pk=pk)

    actor = _actor_or_fallback_user(request)
    NursingNote.objects.create(
        patient_record=patient,
        created_by=actor,
        note_type=request.POST.get("note_type", "progress"),
        pain_score=pain_score,
        mobility_status=request.POST.get("mobility_status", "").strip(),
        intake_output=request.POST.get("intake_output", "").strip(),
        escalated_to=request.POST.get("escalated_to", "").strip(),
        note_text=note_text,
    )
    log_record_access(
        user=actor,
        patient_record=patient,
        action=AccessLog.AccessAction.UPDATE,
        request=request,
        notes="Nursing note added",
    )
    _log_audit_event(
        request,
        action_type="add_nursing_note",
        patient_ref=patient.hospital_id,
        details="Nursing note created",
    )
    messages.success(request, "Nursing note saved.")
    return redirect("hrms-patient-record", pk=pk)


@role_guard("nurse")
def shift_handover_page(request: HttpRequest) -> HttpResponse:
    today = timezone.now().date()
    todays_vitals = NursingVital.objects.filter(recorded_at__date=today).count()
    todays_notes = NursingNote.objects.filter(created_at__date=today).count()
    flagged_open = AccessLog.objects.filter(is_flagged=True, alert_status=AccessLog.AlertStatus.OPEN).count()

    context = _build_context(
        request,
        page_title="Shift Handover",
        page_name="Shift Handover Summary",
        page_note="Auto-generated summary with pending tasks checklist.",
    )
    context["auto_summary"] = (
        f"{todays_vitals} vitals entries and {todays_notes} nursing notes were recorded this shift. "
        f"{flagged_open} open security/behavior alerts remain under review."
    )
    context["pending_tasks"] = [
        "PAT-000342: 10:00 vitals recheck",
        "PAT-000501: oxygen saturation follow-up note",
        "PAT-000581: pain reassessment documentation",
        "Ward C handover medication exception review",
        "Receiving nurse acknowledgement",
    ]
    return render(request, "hrms/shift_handover.html", context)


@role_guard("nurse")
@require_POST
def signoff_handover_action(request: HttpRequest) -> HttpResponse:
    notes = request.POST.get("handover_note", "").strip()
    _log_audit_event(
        request,
        action_type="handover_signoff",
        details=notes or "Shift handover signed",
    )
    messages.success(request, "Handover summary signed and submitted.")
    return redirect("hrms-shift-handover")


@role_guard("admin")
def audit_logs_page(request: HttpRequest) -> HttpResponse:
    context = _build_context(
        request,
        page_title="Audit Logs",
        page_name="Audit Logs",
        page_note="Read-only forensic trail of record access and security-relevant actions.",
    )
    queryset = _filter_audit_events(request)[:500]
    context["audit_rows"] = [
        {
            "time": event.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "user": f"{event.user.username.upper()} / {_format_name(event.user)}" if event.user else "SYSTEM",
            "action": event.action_type,
            "patient": event.patient_ref or "-",
            "ip_device": f"{event.ip_address or '-'} / {event.device or '-'}",
            "outcome": event.outcome.title(),
        }
        for event in queryset
    ]
    context["filters"] = {
        "date_from": request.GET.get("date_from", ""),
        "date_to": request.GET.get("date_to", ""),
        "user": request.GET.get("user", ""),
        "department": request.GET.get("department", ""),
        "patient_ref": request.GET.get("patient_ref", ""),
        "action_type": request.GET.get("action_type", ""),
    }
    return render(request, "hrms/audit_logs.html", context)


@role_guard("admin")
def export_audit_csv(request: HttpRequest) -> HttpResponse:
    role = _get_role(request)
    if not ROLE_CONFIG[role]["can_export_audit"]:
        messages.error(request, "You don't have permission to export audit logs.")
        _log_audit_event(
            request,
            action_type="export_audit_denied",
            outcome=AuditEvent.Outcome.DENIED,
            details="RBAC blocked audit export",
        )
        return redirect("hrms-audit-logs")

    queryset = _filter_audit_events(request)[:5000]
    buffer = StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["Timestamp", "User", "Action", "PatientRef", "IP", "Device", "Outcome", "Details"])
    for event in queryset:
        writer.writerow(
            [
                event.timestamp.isoformat(),
                event.user.username if event.user else "SYSTEM",
                event.action_type,
                event.patient_ref,
                event.ip_address or "",
                event.device,
                event.outcome,
                event.details,
            ]
        )

    _log_audit_event(request, action_type="export_audit_csv", details=f"Exported {queryset.count()} rows")
    response = HttpResponse(buffer.getvalue(), content_type="text/csv")
    response["Content-Disposition"] = "attachment; filename=audit_logs_export.csv"
    return response


@role_guard("admin")
def alerts_page(request: HttpRequest) -> HttpResponse:
    context = _build_context(
        request,
        page_title="Anomaly Alerts",
        page_name="Anomaly Alerts & Investigations",
        page_note="Review risk-scored alerts, triage, and escalate to investigations.",
    )
    alerts_qs = AccessLog.objects.select_related("user", "patient_record", "assigned_investigator").filter(is_flagged=True).order_by(
        "-risk_score", "-accessed_at"
    )
    selected_id = request.GET.get("alert")
    selected_alert = None
    if selected_id:
        selected_alert = alerts_qs.filter(id=selected_id).first()
    if not selected_alert:
        selected_alert = alerts_qs.first()

    context["alerts"] = [
        {
            "id": f"ALT-{alert.id:05d}",
            "pk": alert.id,
            "severity": (alert.alert_severity or AccessLog.AlertSeverity.MEDIUM).title(),
            "status": alert.alert_status.title(),
            "risk_score": int(alert.risk_score or round((alert.anomaly_score or 0.5) * 100)),
            "summary": alert.notes or "Anomaly detected in access behavior",
        }
        for alert in alerts_qs[:120]
    ]
    context["selected_alert"] = selected_alert
    context["investigators"] = User.objects.filter(
        profile__role=RoleChoices.ADMIN
    ).order_by("username")
    context["case_options"] = InvestigationCase.objects.order_by("-opened_at")[:20]
    return render(request, "hrms/alerts.html", context)


@role_guard("admin")
@require_POST
def triage_alert_action(request: HttpRequest, alert_id: int) -> HttpResponse:
    alert = get_object_or_404(AccessLog, id=alert_id, is_flagged=True)
    investigator_id = request.POST.get("investigator_id")
    triage_notes = request.POST.get("triage_notes", "").strip()
    case_reference = request.POST.get("case_reference", "").strip()

    investigator = User.objects.filter(id=investigator_id).first() if investigator_id else None
    if case_reference:
        case = InvestigationCase.objects.filter(case_reference=case_reference).first()
        if not case:
            case = InvestigationCase.objects.create(
                case_reference=case_reference,
                title=f"Investigation for {case_reference}",
                summary="Created during alert triage.",
                status=InvestigationCase.CaseStatus.IN_REVIEW,
                owner=investigator or _actor_user(request),
                opened_by=_actor_user(request),
            )
    else:
        case = InvestigationCase.objects.order_by("-opened_at").first()

    alert.alert_status = AccessLog.AlertStatus.TRIAGED
    alert.assigned_investigator = investigator
    alert.triage_notes = triage_notes
    alert.case_reference = case.case_reference if case else alert.case_reference
    if not alert.alert_severity:
        alert.alert_severity = AccessLog.AlertSeverity.MEDIUM
    if not alert.risk_score and alert.anomaly_score is not None:
        alert.risk_score = round(alert.anomaly_score * 100, 2)
    alert.save(
        update_fields=[
            "alert_status",
            "assigned_investigator",
            "triage_notes",
            "case_reference",
            "alert_severity",
            "risk_score",
        ]
    )

    _log_audit_event(
        request,
        action_type="triage_alert",
        target_ref=f"ALT-{alert.id:05d}",
        patient_ref=alert.patient_record.hospital_id if alert.patient_record else "",
        details=f"Case={alert.case_reference}",
    )
    messages.success(request, f"Alert ALT-{alert.id:05d} triaged successfully.")
    return redirect(f"{reverse('hrms-alerts')}?alert={alert.id}")


@role_guard("admin")
@require_POST
def close_alert_action(request: HttpRequest, alert_id: int) -> HttpResponse:
    alert = get_object_or_404(AccessLog, id=alert_id, is_flagged=True)
    closure_reason = request.POST.get("closure_reason", "").strip()
    final_note = request.POST.get("final_note", "").strip()

    alert.alert_status = AccessLog.AlertStatus.CLOSED
    alert.closed_reason = closure_reason or "Closed by analyst review"
    alert.triage_notes = f"{alert.triage_notes}\n{final_note}".strip()
    alert.save(update_fields=["alert_status", "closed_reason", "triage_notes"])

    _log_audit_event(
        request,
        action_type="close_alert",
        target_ref=f"ALT-{alert.id:05d}",
        patient_ref=alert.patient_record.hospital_id if alert.patient_record else "",
        details=alert.closed_reason,
    )
    messages.success(request, f"Alert ALT-{alert.id:05d} closed.")
    return redirect(f"{reverse('hrms-alerts')}?alert={alert.id}")


@role_guard("admin")
def investigations_page(request: HttpRequest) -> HttpResponse:
    context = _build_context(
        request,
        page_title="Investigation Cases",
        page_name="Investigation Case",
        page_note="Link related alerts, track case notes, and close with disposition.",
    )
    cases = InvestigationCase.objects.select_related("owner", "opened_by").all()
    selected_reference = request.GET.get("case", "")
    selected_case = cases.filter(case_reference=selected_reference).first() if selected_reference else cases.first()

    linked_alerts = []
    case_notes = []
    if selected_case:
        linked_alerts = AccessLog.objects.select_related("patient_record").filter(
            is_flagged=True,
            case_reference=selected_case.case_reference,
        )
        case_notes = selected_case.notes.select_related("author").all()

    context["cases"] = cases
    context["selected_case"] = selected_case
    context["linked_alerts"] = linked_alerts
    context["case_notes"] = case_notes
    return render(request, "hrms/investigations.html", context)


@role_guard("admin")
@require_POST
def add_case_note_action(request: HttpRequest, case_id: int) -> HttpResponse:
    case = get_object_or_404(InvestigationCase, id=case_id)
    note = request.POST.get("note", "").strip()
    if not note:
        messages.error(request, "Case note cannot be empty.")
        return redirect(f"{reverse('hrms-investigations')}?case={case.case_reference}")

    InvestigationCaseNote.objects.create(
        case=case,
        author=_actor_user(request),
        note=note,
    )
    if case.status == InvestigationCase.CaseStatus.OPEN:
        case.status = InvestigationCase.CaseStatus.IN_REVIEW
        case.save(update_fields=["status", "updated_at"])

    _log_audit_event(
        request,
        action_type="add_case_note",
        target_ref=case.case_reference,
        details="Investigation note added",
    )
    messages.success(request, "Case note added.")
    return redirect(f"{reverse('hrms-investigations')}?case={case.case_reference}")


@role_guard("admin")
@require_POST
def close_case_action(request: HttpRequest, case_id: int) -> HttpResponse:
    case = get_object_or_404(InvestigationCase, id=case_id)
    disposition = request.POST.get("disposition", "").strip()
    closure_note = request.POST.get("closure_note", "").strip()

    case.status = InvestigationCase.CaseStatus.CLOSED
    case.closed_reason = disposition or "Closed by investigator"
    case.closed_by = _actor_user(request)
    case.closed_at = timezone.now()
    case.summary = f"{case.summary}\nClosure: {closure_note}".strip()
    case.save()

    AccessLog.objects.filter(case_reference=case.case_reference, is_flagged=True).exclude(
        alert_status=AccessLog.AlertStatus.CLOSED
    ).update(
        alert_status=AccessLog.AlertStatus.CLOSED,
        closed_reason=case.closed_reason,
    )

    _log_audit_event(
        request,
        action_type="close_case",
        target_ref=case.case_reference,
        details=case.closed_reason,
    )
    messages.success(request, f"Investigation {case.case_reference} closed.")
    return redirect(f"{reverse('hrms-investigations')}?case={case.case_reference}")


@role_guard("admin")
def export_case_report_action(request: HttpRequest, case_id: int) -> HttpResponse:
    role = _get_role(request)
    case = get_object_or_404(InvestigationCase, id=case_id)
    if not ROLE_CONFIG[role]["can_export_audit"]:
        messages.error(request, "You don't have permission to export investigation reports.")
        _log_audit_event(
            request,
            action_type="export_case_denied",
            outcome=AuditEvent.Outcome.DENIED,
            target_ref=case.case_reference,
        )
        return redirect(f"{reverse('hrms-investigations')}?case={case.case_reference}")

    linked_alerts = AccessLog.objects.filter(case_reference=case.case_reference, is_flagged=True)
    buffer = StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["Case", "Status", "AlertId", "Severity", "RiskScore", "AlertStatus", "Summary"])
    for alert in linked_alerts:
        writer.writerow(
            [
                case.case_reference,
                case.status,
                f"ALT-{alert.id:05d}",
                alert.alert_severity,
                alert.risk_score,
                alert.alert_status,
                alert.notes,
            ]
        )
    _log_audit_event(request, action_type="export_case_report", target_ref=case.case_reference)
    response = HttpResponse(buffer.getvalue(), content_type="text/csv")
    response["Content-Disposition"] = f"attachment; filename={case.case_reference.lower()}_report.csv"
    return response


@role_guard(*tuple(ROLE_CONFIG.keys()))
def user_flow_page(request: HttpRequest) -> HttpResponse:
    context = _build_context(
        request,
        page_title="User Flow Diagram",
        page_name="User Flow",
        page_note="End-to-end flow: authentication, route guards, task execution, and audit creation.",
    )
    return render(request, "hrms/user_flow.html", context)

