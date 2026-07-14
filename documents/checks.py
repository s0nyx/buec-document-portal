from urllib.parse import urlparse

from cryptography.fernet import Fernet
from django.conf import settings
from django.core.checks import Error, Warning, register


@register()
def portal_security_checks(app_configs, **kwargs):
    messages = []

    for key in settings.FILE_ENCRYPTION_KEYS:
        try:
            Fernet(key.encode())
        except Exception:
            messages.append(
                Error(
                    "FILE_ENCRYPTION_KEYS contains an invalid Fernet key.",
                    id="documents.E001",
                )
            )

    parsed = urlparse(settings.PUBLIC_BASE_URL)
    if not settings.DEBUG and not settings.TESTING and parsed.scheme != "https":
        messages.append(
            Error(
                "PUBLIC_BASE_URL must use HTTPS in production.",
                id="documents.E002",
            )
        )

    if not settings.DEBUG and not settings.TESTING and not settings.REDIS_URL:
        messages.append(
            Warning(
                "REDIS_URL is not configured; rate limits will not be shared across processes.",
                id="documents.W001",
            )
        )

    if (
        not settings.DEBUG
        and not settings.TESTING
        and settings.DATABASES["default"]["ENGINE"].endswith("sqlite3")
    ):
        messages.append(
            Warning(
                "SQLite is not recommended for the production portal.",
                id="documents.W002",
            )
        )

    if settings.REQUIRE_MALWARE_SCAN and not (
        settings.CLAMAV_HOST or settings.CLAMAV_UNIX_SOCKET
    ):
        messages.append(
            Error(
                "REQUIRE_MALWARE_SCAN=true requires CLAMAV_HOST or CLAMAV_UNIX_SOCKET.",
                id="documents.E003",
            )
        )

    return messages
