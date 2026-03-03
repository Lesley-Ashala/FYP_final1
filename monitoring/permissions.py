from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.http import HttpRequest

from monitoring.models import RoleChoices


def get_user_role(user) -> str:
    if not user or not user.is_authenticated:
        return ""
    if user.is_superuser:
        return RoleChoices.ADMIN
    profile = getattr(user, "profile", None)
    if profile:
        if profile.role in {"super_admin", "records_admin", "auditor", "security_officer"}:
            return RoleChoices.ADMIN
        if profile.role == "doctor_clinician":
            return RoleChoices.DOCTOR
        return profile.role
    return RoleChoices.NURSE


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
