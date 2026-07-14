from __future__ import annotations

import hashlib
import logging

from django.db import transaction
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_GET, require_http_methods

from .crypto import (
    consume_token_digest,
    encrypt_bytes,
    hash_upload_token,
    is_well_formed_token,
)
from .forms import UploadDocumentForm
from .models import AuditEvent, DocumentRequest
from .security import client_ip_hash, consume_rate_limit
from .services import (
    record_event,
    safe_email_error_code,
    send_upload_confirmation_email,
)

logger = logging.getLogger(__name__)


def _no_action_response(request: HttpRequest) -> HttpResponse:
    response = render(request, "documents/public/nothing_to_do.html")
    response.headers["Cache-Control"] = "no-store"
    return response


@never_cache
@require_GET
def home(request: HttpRequest) -> HttpResponse:
    response = render(request, "documents/public/home.html")
    response.headers["Cache-Control"] = "no-store"
    return response


@never_cache
@csrf_protect
@require_http_methods(["GET", "POST"])
def upload_document(request: HttpRequest, token: str) -> HttpResponse:
    if not is_well_formed_token(token):
        return _no_action_response(request)

    token_digest = hash_upload_token(token)
    document_request = DocumentRequest.objects.filter(token_digest=token_digest).first()
    if not document_request:
        return _no_action_response(request)

    if document_request.status != DocumentRequest.Status.PENDING:
        return _no_action_response(request)

    if document_request.expires_at <= timezone.now():
        with transaction.atomic():
            locked = DocumentRequest.objects.select_for_update().get(
                pk=document_request.pk
            )
            if locked.status == DocumentRequest.Status.PENDING:
                locked.status = DocumentRequest.Status.EXPIRED
                locked.token_digest = consume_token_digest()
                locked.save(update_fields=["status", "token_digest", "updated_at"])
                record_event(
                    AuditEvent.Event.REQUEST_EXPIRED,
                    document_request=locked,
                    ip_hash=client_ip_hash(request),
                )
        return _no_action_response(request)

    form = UploadDocumentForm(request.POST or None, request.FILES or None)
    if request.method == "POST":
        limited, _ = consume_rate_limit(
            "public-upload",
            [client_ip_hash(request), token_digest],
            limit=8,
            window_seconds=60 * 60,
        )
        if limited:
            form.add_error(None, "Too many upload attempts. Please try again later.")
            response = render(
                request,
                "documents/public/upload.html",
                {"form": form, "request_item": document_request},
                status=429,
            )
            response.headers["Retry-After"] = "3600"
            response.headers["Cache-Control"] = "no-store"
            return response

        if form.is_valid() and form.validated_document:
            validated = form.validated_document
            saved_name = ""
            with transaction.atomic():
                locked = DocumentRequest.objects.select_for_update().get(
                    pk=document_request.pk
                )
                if (
                    locked.token_digest != token_digest
                    or locked.status != DocumentRequest.Status.PENDING
                    or locked.expires_at <= timezone.now()
                ):
                    return _no_action_response(request)

                encrypted_file = encrypt_bytes(validated.plain_bytes)
                locked.uploaded_file.save("document.bin", encrypted_file, save=False)
                saved_name = locked.uploaded_file.name
                locked.original_filename = validated.safe_filename
                locked.detected_mime = validated.detected_mime
                locked.file_size = validated.size
                locked.file_sha256 = hashlib.sha256(validated.plain_bytes).hexdigest()
                locked.uploaded_ip_hash = client_ip_hash(request)
                locked.uploaded_at = timezone.now()
                locked.status = DocumentRequest.Status.ACTION_REQUIRED
                locked.token_digest = consume_token_digest()
                try:
                    locked.save()
                except Exception:
                    if saved_name:
                        locked.uploaded_file.storage.delete(saved_name)
                    raise
                record_event(
                    AuditEvent.Event.DOCUMENT_UPLOADED,
                    document_request=locked,
                    ip_hash=client_ip_hash(request),
                    details={
                        "size": validated.size,
                        "mime": validated.detected_mime,
                        "sha256": locked.file_sha256,
                    },
                )

            try:
                send_upload_confirmation_email(locked)
            except Exception as exc:
                logger.exception("Unable to send confirmation email for %s", locked.pk)
                record_event(
                    AuditEvent.Event.CONFIRMATION_EMAIL_FAILED,
                    document_request=locked,
                    ip_hash=client_ip_hash(request),
                    details={"error_code": safe_email_error_code(exc)},
                )
            else:
                locked.confirmation_email_sent_at = timezone.now()
                locked.save(update_fields=["confirmation_email_sent_at", "updated_at"])
                record_event(
                    AuditEvent.Event.CONFIRMATION_EMAIL_SENT,
                    document_request=locked,
                    ip_hash=client_ip_hash(request),
                )
            return redirect("upload-success")

    response = render(
        request,
        "documents/public/upload.html",
        {"form": form, "request_item": document_request},
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@never_cache
@require_GET
def upload_success(request: HttpRequest) -> HttpResponse:
    response = render(request, "documents/public/success.html")
    response.headers["Cache-Control"] = "no-store"
    return response


@require_GET
def robots(request: HttpRequest) -> HttpResponse:
    return HttpResponse("User-agent: *\nDisallow: /\n", content_type="text/plain")


def bad_request(request: HttpRequest, exception=None) -> HttpResponse:
    return render(
        request, "documents/public/error.html", {"error_code": "400"}, status=400
    )


def permission_denied(request: HttpRequest, exception=None) -> HttpResponse:
    return render(
        request, "documents/public/error.html", {"error_code": "403"}, status=403
    )


def not_found(request: HttpRequest, exception=None) -> HttpResponse:
    return render(
        request, "documents/public/error.html", {"error_code": "404"}, status=404
    )


def server_error(request: HttpRequest) -> HttpResponse:
    return render(
        request, "documents/public/error.html", {"error_code": "500"}, status=500
    )
