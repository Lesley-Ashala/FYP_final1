from pathlib import Path

import os


BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = "django-insecure-change-this-in-production"

DEBUG = True

ALLOWED_HOSTS: list[str] = []

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "monitoring.apps.MonitoringConfig",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "hospital_monitor.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "monitoring.context_processors.user_role",
                "monitoring.context_processors.hrms_nav",
            ],
        },
    },
]

WSGI_APPLICATION = "hospital_monitor.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "patient-list"
LOGOUT_REDIRECT_URL = "login"


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_csv(name: str, default: str = "") -> list[str]:
    raw = os.environ.get(name, default)
    parts = [p.strip() for p in raw.split(",")]
    return [p for p in parts if p]


# Mailjet (transactional alerts)
MAILJET_API_KEY_PUBLIC = os.environ.get("MJ_APIKEY_PUBLIC", "") or os.environ.get(
    "MAILJET_API_KEY_PUBLIC", ""
)
MAILJET_API_KEY_PRIVATE = os.environ.get("MJ_APIKEY_PRIVATE", "") or os.environ.get(
    "MAILJET_API_KEY_PRIVATE", ""
)
MAILJET_FROM_EMAIL = os.environ.get("MAILJET_FROM_EMAIL", "")
MAILJET_FROM_NAME = os.environ.get("MAILJET_FROM_NAME", "Hospital Monitor")

# Comma-separated recipients. Default matches your request.
ALERT_EMAIL_TO = _env_csv("ALERT_EMAIL_TO", "gmutakura8@gmail.com")

# Controls whether the app attempts to send alert emails.
# If enabled but credentials are missing, sending will fail with a clear log message.
ALERT_EMAIL_ENABLED = _env_bool("ALERT_EMAIL_ENABLED", True)


LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {"class": "logging.StreamHandler"},
    },
    "loggers": {
        "monitoring.notifications": {
            "handlers": ["console"],
            "level": "INFO",
        },
    },
}
