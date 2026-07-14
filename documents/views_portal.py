from __future__ import annotations

import logging
from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login, logout
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Q
from django.http import FileResponse, HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from .access import has_portal_access, portal_access_required
from .crypto import (
    consume_token_digest,
    decrypt_field_file,
    issue_upload_token,
)
from .forms import NewDocumentRequestForm, StyledAuthenticationForm
from .models import AuditEvent, DocumentRequest
from .security import (
    clear_rate_limit,
    client_ip_hash,
    consume_rate_limit,
    hash_sensitive_value,
)
from .services import (
    expire_stale_document_requests,
    record_event,
    safe_email_error_code,
    send_document_request_email,
)

logger = logging.getLogger(__name__)

VALID_STATUS_FILTERS = {
    "all",
    DocumentRequest.Status.PENDING,
    DocumentRequest.Status.ACTION_REQUIRED,
    DocumentRequest.Status.COMPLETED,
    DocumentRequest.Status.CANCELLED,
    DocumentRequest.Status.EXPIRED,
}


def _wants_json(request: HttpRequest) -> bool:
    return "application/json" in request.headers.get("Accept", "")


def _expire_stale_requests() -> None:
    expire_stale_document_requests(max_items=500)


def _filtered_queryset(request: HttpRequest):
    _expire_stale_requests()
    query = request.GET.get("q", "").strip()[:120]
    status_filter = request.GET.get("status", "all").strip()
    if status_filter not in VALID_STATUS_FILTERS:
        status_filter = "all"

    queryset = DocumentRequest.objects.select_related("requested_by").all()
    if query:
        queryset = queryset.filter(
            Q(student_name__icontains=query)
            | Q(student_email__icontains=query)
            | Q(other_document_name__icontains=query)
        )
    if status_filter != "all":
        queryset = queryset.filter(status=status_filter)
    return queryset, query, status_filter


def _table_context(request: HttpRequest) -> dict:
    queryset, query, status_filter = _filtered_queryset(request)
    paginator = Paginator(queryset, 10)
    page_obj = paginator.get_page(request.GET.get("page", 1))
    return {
        "page_obj": page_obj,
        "query": query,
        "status_filter": status_filter,
    }


@never_cache
@require_http_methods(["GET", "POST"])
def portal_login(request: HttpRequest) -> HttpResponse:
    if has_portal_access(request.user):
        return redirect("portal:dashboard")

    next_url = request.GET.get("next", "") or request.POST.get("next", "")
    form = StyledAuthenticationForm(request=request, data=request.POST or None)

    if request.method == "POST":
        username = request.POST.get("username", "").strip().lower()[:150]
        ip_hash = client_ip_hash(request)
        username_hash = hash_sensitive_value(username or "empty")
        rate_parts = [ip_hash, username_hash]
        limited_pair, _ = consume_rate_limit(
            "portal-login", rate_parts, limit=8, window_seconds=15 * 60
        )
        limited_ip, _ = consume_rate_limit(
            "portal-login-ip", [ip_hash], limit=40, window_seconds=15 * 60
        )
        if limited_pair or limited_ip:
            form.add_error(None, "Too many sign-in attempts. Please try again later.")
            response = render(
                request,
                "documents/portal/login.html",
                {"form": form, "next": next_url},
                status=429,
            )
            response.headers["Retry-After"] = "900"
            return response

        if form.is_valid() and has_portal_access(form.get_user()):
            user = form.get_user()
            login(request, user)
            request.session.cycle_key()
            clear_rate_limit("portal-login", rate_parts)
            record_event(
                AuditEvent.Event.PORTAL_LOGIN,
                actor=user,
                ip_hash=ip_hash,
            )
            if next_url and url_has_allowed_host_and_scheme(
                next_url,
                allowed_hosts={request.get_host()},
                require_https=request.is_secure(),
            ):
                return redirect(next_url)
            return redirect("portal:dashboard")

        record_event(
            AuditEvent.Event.PORTAL_LOGIN_FAILED,
            ip_hash=ip_hash,
            details={"username_hash": username_hash},
        )
        # Replace detailed authentication errors with a generic message.
        form.errors.pop("__all__", None)
        form.add_error(None, "Unable to sign in with those credentials.")

    response = render(
        request,
        "documents/portal/login.html",
        {"form": form, "next": next_url},
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@require_POST
@portal_access_required
def portal_logout(request: HttpRequest) -> HttpResponse:
    logout(request)
    return redirect("portal:login")


@never_cache
@require_GET
@portal_access_required
def dashboard(request: HttpRequest) -> HttpResponse:
    context = _table_context(request)
    context.update(
        {
            "new_request_form": NewDocumentRequestForm(),
            "stats": {
                "pending": DocumentRequest.objects.filter(
                    status=DocumentRequest.Status.PENDING
                ).count(),
                "action": DocumentRequest.objects.filter(
                    status=DocumentRequest.Status.ACTION_REQUIRED
                ).count(),
                "completed": DocumentRequest.objects.filter(
                    status=DocumentRequest.Status.COMPLETED
                ).count(),
                "total": DocumentRequest.objects.count(),
            },
        }
    )
    response = render(request, "documents/portal/dashboard.html", context)
    response.headers["Cache-Control"] = "no-store"
    return response


@never_cache
@require_GET
@portal_access_required
def request_table(request: HttpRequest) -> HttpResponse:
    response = render(
        request,
        "documents/portal/_request_table.html",
        _table_context(request),
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@require_POST
@portal_access_required
def create_request(request: HttpRequest) -> HttpResponse:
    limited, _ = consume_rate_limit(
        "create-request",
        [str(request.user.pk), client_ip_hash(request)],
        limit=60,
        window_seconds=60 * 60,
    )
    if limited:
        payload = {"ok": False, "message": "Request limit reached. Try again later."}
        return JsonResponse(payload, status=429)

    form = NewDocumentRequestForm(request.POST)
    if not form.is_valid():
        if _wants_json(request):
            return JsonResponse(
                {
                    "ok": False,
                    "errors": {
                        field: [str(message) for message in errors]
                        for field, errors in form.errors.items()
                    },
                },
                status=422,
            )
        messages.error(request, "Please correct the highlighted fields.")
        return redirect("portal:dashboard")

    token = issue_upload_token()
    now = timezone.now()
    document_request = DocumentRequest.objects.create(
        student_name=form.cleaned_data["student_name"],
        student_email=form.cleaned_data["student_email"],
        document_type=form.cleaned_data["document_type"],
        other_document_name=form.cleaned_data["other_document_name"],
        requested_by=request.user,
        token_digest=token.digest,
        token_created_at=now,
        expires_at=now + timedelta(days=settings.UPLOAD_TOKEN_LIFETIME_DAYS),
    )
    record_event(
        AuditEvent.Event.REQUEST_CREATED,
        document_request=document_request,
        actor=request.user,
        ip_hash=client_ip_hash(request),
    )

    email_sent = False
    try:
        send_document_request_email(document_request, token.raw)
    except (
        Exception
    ) as exc:  # SMTP and backend failures are intentionally generic to the UI.
        logger.exception(
            "Unable to send document request email for %s", document_request.pk
        )
        document_request.email_status = DocumentRequest.EmailStatus.FAILED
        document_request.email_error_code = safe_email_error_code(exc)
        document_request.save(
            update_fields=["email_status", "email_error_code", "updated_at"]
        )
        record_event(
            AuditEvent.Event.REQUEST_EMAIL_FAILED,
            document_request=document_request,
            actor=request.user,
            ip_hash=client_ip_hash(request),
            details={"error_code": document_request.email_error_code},
        )
    else:
        email_sent = True
        document_request.email_status = DocumentRequest.EmailStatus.SENT
        document_request.email_error_code = ""
        document_request.email_sent_at = timezone.now()
        document_request.save(
            update_fields=[
                "email_status",
                "email_error_code",
                "email_sent_at",
                "updated_at",
            ]
        )
        record_event(
            AuditEvent.Event.REQUEST_EMAIL_SENT,
            document_request=document_request,
            actor=request.user,
            ip_hash=client_ip_hash(request),
        )

    if email_sent:
        message = "The request was created and the email was sent."
        messages.success(request, message)
    else:
        message = "The request was saved, but the email could not be sent. Use Resend after checking SMTP settings."
        messages.warning(request, message)

    if _wants_json(request):
        return JsonResponse(
            {
                "ok": True,
                "email_sent": email_sent,
                "message": message,
                "redirect": reverse("portal:dashboard"),
            },
            status=201,
        )
    return redirect("portal:dashboard")


@require_POST
@portal_access_required
def resend_request(request: HttpRequest, request_id) -> HttpResponse:
    document_request = get_object_or_404(DocumentRequest, pk=request_id)
    if document_request.status not in {
        DocumentRequest.Status.PENDING,
        DocumentRequest.Status.EXPIRED,
    }:
        messages.error(request, "This request can no longer be resent.")
        return redirect("portal:dashboard")

    limited, _ = consume_rate_limit(
        "resend-request",
        [str(request.user.pk), str(document_request.pk)],
        limit=6,
        window_seconds=60 * 60,
    )
    if limited:
        messages.error(request, "Too many resend attempts for this request.")
        return redirect("portal:dashboard")

    token = issue_upload_token()
    now = timezone.now()
    document_request.token_digest = token.digest
    document_request.token_created_at = now
    document_request.expires_at = now + timedelta(
        days=settings.UPLOAD_TOKEN_LIFETIME_DAYS
    )
    document_request.status = DocumentRequest.Status.PENDING
    document_request.email_status = DocumentRequest.EmailStatus.NOT_SENT
    document_request.email_error_code = ""
    document_request.save(
        update_fields=[
            "token_digest",
            "token_created_at",
            "expires_at",
            "status",
            "email_status",
            "email_error_code",
            "updated_at",
        ]
    )

    try:
        send_document_request_email(document_request, token.raw)
    except Exception as exc:
        logger.exception(
            "Unable to resend document request email for %s", document_request.pk
        )
        document_request.email_status = DocumentRequest.EmailStatus.FAILED
        document_request.email_error_code = safe_email_error_code(exc)
        document_request.save(
            update_fields=["email_status", "email_error_code", "updated_at"]
        )
        record_event(
            AuditEvent.Event.REQUEST_EMAIL_FAILED,
            document_request=document_request,
            actor=request.user,
            ip_hash=client_ip_hash(request),
            details={"error_code": document_request.email_error_code},
        )
        messages.error(
            request, "The new link was created, but the email could not be sent."
        )
    else:
        document_request.email_status = DocumentRequest.EmailStatus.SENT
        document_request.email_sent_at = timezone.now()
        document_request.save(
            update_fields=["email_status", "email_sent_at", "updated_at"]
        )
        record_event(
            AuditEvent.Event.REQUEST_RESENT,
            document_request=document_request,
            actor=request.user,
            ip_hash=client_ip_hash(request),
        )
        messages.success(
            request, "A fresh single-use upload link was emailed to the student."
        )
    return redirect("portal:dashboard")


@require_POST
@portal_access_required
def complete_request(request: HttpRequest, request_id) -> HttpResponse:
    with transaction.atomic():
        document_request = get_object_or_404(
            DocumentRequest.objects.select_for_update(), pk=request_id
        )
        if document_request.status != DocumentRequest.Status.ACTION_REQUIRED:
            messages.error(request, "Only requests awaiting action can be completed.")
            return redirect("portal:dashboard")
        document_request.status = DocumentRequest.Status.COMPLETED
        document_request.completed_at = timezone.now()
        document_request.save(update_fields=["status", "completed_at", "updated_at"])
        record_event(
            AuditEvent.Event.REQUEST_COMPLETED,
            document_request=document_request,
            actor=request.user,
            ip_hash=client_ip_hash(request),
        )
    messages.success(request, "The request was marked as completed.")
    return redirect("portal:dashboard")


@require_POST
@portal_access_required
def cancel_request(request: HttpRequest, request_id) -> HttpResponse:
    with transaction.atomic():
        document_request = get_object_or_404(
            DocumentRequest.objects.select_for_update(), pk=request_id
        )
        if document_request.status not in {
            DocumentRequest.Status.PENDING,
            DocumentRequest.Status.EXPIRED,
        }:
            messages.error(
                request, "This request cannot be cancelled in its current status."
            )
            return redirect("portal:dashboard")
        document_request.status = DocumentRequest.Status.CANCELLED
        document_request.cancelled_at = timezone.now()
        document_request.token_digest = consume_token_digest()
        document_request.save(
            update_fields=["status", "cancelled_at", "token_digest", "updated_at"]
        )
        record_event(
            AuditEvent.Event.REQUEST_CANCELLED,
            document_request=document_request,
            actor=request.user,
            ip_hash=client_ip_hash(request),
        )
    messages.success(
        request, "The request was cancelled and its upload link was invalidated."
    )
    return redirect("portal:dashboard")


@never_cache
@require_GET
@portal_access_required
def download_document(request: HttpRequest, request_id) -> HttpResponse:
    document_request = get_object_or_404(DocumentRequest, pk=request_id)
    if (
        document_request.status
        not in {
            DocumentRequest.Status.ACTION_REQUIRED,
            DocumentRequest.Status.COMPLETED,
        }
        or not document_request.has_file
    ):
        messages.error(request, "No uploaded document is available for this request.")
        return redirect("portal:dashboard")

    limited, _ = consume_rate_limit(
        "download-document",
        [str(request.user.pk), client_ip_hash(request)],
        limit=120,
        window_seconds=60 * 60,
    )
    if limited:
        return HttpResponse("Download limit reached.", status=429)

    try:
        file_object = decrypt_field_file(document_request.uploaded_file)
    except Exception:
        logger.exception("Unable to decrypt document %s", document_request.pk)
        return HttpResponse("The document could not be opened.", status=500)

    record_event(
        AuditEvent.Event.DOCUMENT_DOWNLOADED,
        document_request=document_request,
        actor=request.user,
        ip_hash=client_ip_hash(request),
        details={"sha256": document_request.file_sha256},
    )
    response = FileResponse(
        file_object,
        as_attachment=True,
        filename=document_request.original_filename,
        content_type="application/octet-stream",
    )
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response
