from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.http import HttpRequest

import json

from monitoring.models import RoleChoices, SystemSetting

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


def get_user_role(user) -> str:
    if not user or not user.is_authenticated:
        return ""
    if user.is_superuser:
        return RoleChoices.ADMIN
    profile = getattr(user, "profile", None)
    if profile:
        return profile.role
    return RoleChoices.NURSE


def get_permissions_matrix() -> dict:
    setting = SystemSetting.objects.filter(key="permissions_matrix").first()
    if setting:
        try:
            return json.loads(setting.value)
        except json.JSONDecodeError:
            return DEFAULT_PERMISSION_MATRIX
    return DEFAULT_PERMISSION_MATRIX


def has_permission(user, permission_key: str) -> bool:
    if not user or not user.is_authenticated:
        return False
    role = get_user_role(user)
    matrix = get_permissions_matrix()
    return bool(matrix.get(role, {}).get(permission_key, False))


def user_has_any_role(user, roles: tuple[str, ...]) -> bool:
    if not user or not user.is_authenticated:
        return False
    role = get_user_role(user)
    return role in roles


class RoleRequiredMixin(LoginRequiredMixin, UserPassesTestMixin):
    allowed_roles: tuple[str, ...] = ()

    def test_func(self) -> bool:
        request: HttpRequest = self.request
        return user_has_any_role(request.user, self.allowed_roles)
