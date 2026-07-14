from __future__ import annotations

from functools import wraps
from urllib.parse import quote

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.urls import reverse


def has_portal_access(user) -> bool:
    if not user.is_authenticated:
        return False
    if settings.PORTAL_SUPERUSER_ONLY:
        return bool(user.is_superuser)
    return bool(user.is_staff or user.is_superuser)


def portal_access_required(view_func):
    @wraps(view_func)
    def wrapped(request: HttpRequest, *args, **kwargs) -> HttpResponse:
        if not request.user.is_authenticated:
            login_url = reverse("portal:login")
            return redirect(f"{login_url}?next={quote(request.get_full_path())}")
        if not has_portal_access(request.user):
            raise PermissionDenied
        return view_func(request, *args, **kwargs)

    return wrapped
