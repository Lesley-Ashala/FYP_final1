from monitoring.permissions import get_user_role
from monitoring.hrms_views import NAV_ITEMS, _get_role


def user_role(request):
    return {"user_role": get_user_role(request.user)}


def hrms_nav(request):
    """Provide HRMS navigation items for the top nav bar on all pages.

    Uses the same NAV_ITEMS and role resolution as the HRMS views so that
    base.html can always render a consistent, role-aware navigation bar.
    """

    # If there is no resolver match (e.g. error pages), do nothing.
    if not getattr(request, "resolver_match", None):
        return {}

    role = _get_role(request)
    active_url_name = request.resolver_match.url_name or ""
    nav = [item for item in NAV_ITEMS if role in item["roles"]]

    return {
        "nav_items": nav,
        "active_url_name": active_url_name,
    }
