from __future__ import annotations

import logging
from urllib.parse import urljoin

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.db import transaction
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone

from .crypto import consume_token_digest
from .models import AuditEvent, DocumentRequest

logger = logging.getLogger(__name__)


def upload_url(raw_token: str) -> str:
    path = reverse("document-upload", kwargs={"token": raw_token})
    return urljoin(f"{settings.PUBLIC_BASE_URL}/", path.lstrip("/"))


def send_document_request_email(
    document_request: DocumentRequest, raw_token: str
) -> None:
    context = {
        "request_item": document_request,
        "document_label": document_request.document_label,
        "upload_url": upload_url(raw_token),
        "expiry": timezone.localtime(document_request.expires_at),
        "brand_name": settings.BRAND_NAME,
        "brand_short_name": settings.BRAND_SHORT_NAME,
        "support_email": settings.SUPPORT_EMAIL,
        "support_phone": settings.SUPPORT_PHONE,
    }
    text_body = render_to_string("documents/emails/request_document.txt", context)
    html_body = render_to_string("documents/emails/request_document.html", context)

    message = EmailMultiAlternatives(
        subject=f"Action required: document requested by {settings.BRAND_SHORT_NAME}",
        body=text_body,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[document_request.student_email],
        reply_to=settings.EMAIL_REPLY_TO,
    )
    message.attach_alternative(html_body, "text/html")
    message.send(fail_silently=False)


def send_upload_confirmation_email(document_request: DocumentRequest) -> None:
    context = {
        "request_item": document_request,
        "document_label": document_request.document_label,
        "brand_name": settings.BRAND_NAME,
        "brand_short_name": settings.BRAND_SHORT_NAME,
        "support_email": settings.SUPPORT_EMAIL,
        "support_phone": settings.SUPPORT_PHONE,
    }
    text_body = render_to_string("documents/emails/upload_confirmation.txt", context)
    html_body = render_to_string("documents/emails/upload_confirmation.html", context)

    message = EmailMultiAlternatives(
        subject=f"Document received by {settings.BRAND_SHORT_NAME}",
        body=text_body,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[document_request.student_email],
        reply_to=settings.EMAIL_REPLY_TO,
    )
    message.attach_alternative(html_body, "text/html")
    message.send(fail_silently=False)


def record_event(
    event: str,
    *,
    document_request: DocumentRequest | None = None,
    actor=None,
    ip_hash: str = "",
    details: dict | None = None,
) -> AuditEvent:
    return AuditEvent.objects.create(
        document_request=document_request,
        actor=actor,
        event=event,
        ip_hash=ip_hash,
        details=details or {},
    )


def safe_email_error_code(exc: Exception) -> str:
    return exc.__class__.__name__[:120]


def expire_stale_document_requests(max_items: int | None = None) -> int:
    queryset = (
        DocumentRequest.objects.filter(
            status=DocumentRequest.Status.PENDING,
            expires_at__lte=timezone.now(),
        )
        .order_by("expires_at")
        .values_list("pk", flat=True)
    )
    if max_items is not None:
        queryset = queryset[:max_items]

    expired_count = 0
    for request_id in list(queryset):
        with transaction.atomic():
            item = DocumentRequest.objects.select_for_update().get(pk=request_id)
            if (
                item.status != DocumentRequest.Status.PENDING
                or item.expires_at > timezone.now()
            ):
                continue
            item.status = DocumentRequest.Status.EXPIRED
            item.token_digest = consume_token_digest()
            item.save(update_fields=["status", "token_digest", "updated_at"])
            record_event(AuditEvent.Event.REQUEST_EXPIRED, document_request=item)
            expired_count += 1
    return expired_count
