from __future__ import annotations

import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone

from .storage import private_upload_path, private_upload_storage


class DocumentRequest(models.Model):
    class DocumentType(models.TextChoices):
        PASSPORT = "passport", "Passport"
        SHARE_CODE = "sharecode", "Share code"
        PROOF_OF_ADDRESS = "proof_of_address", "Proof of address"
        CV = "cv", "CV"
        OTHER = "other", "Other"

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        ACTION_REQUIRED = "action", "Action required"
        COMPLETED = "completed", "Completed"
        CANCELLED = "cancelled", "Cancelled"
        EXPIRED = "expired", "Expired"

    class EmailStatus(models.TextChoices):
        NOT_SENT = "not_sent", "Not sent"
        SENT = "sent", "Sent"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    student_name = models.CharField(max_length=160)
    student_email = models.EmailField(max_length=254, db_index=True)
    document_type = models.CharField(max_length=32, choices=DocumentType.choices)
    other_document_name = models.CharField(max_length=160, blank=True)

    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING,
        db_index=True,
    )
    email_status = models.CharField(
        max_length=20,
        choices=EmailStatus.choices,
        default=EmailStatus.NOT_SENT,
        db_index=True,
    )
    email_error_code = models.CharField(max_length=120, blank=True)

    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="document_requests_created",
    )

    token_digest = models.CharField(max_length=64, unique=True)
    token_created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField(db_index=True)

    uploaded_file = models.FileField(
        storage=private_upload_storage,
        upload_to=private_upload_path,
        blank=True,
        max_length=255,
    )
    original_filename = models.CharField(max_length=220, blank=True)
    detected_mime = models.CharField(max_length=120, blank=True)
    file_size = models.PositiveBigIntegerField(null=True, blank=True)
    file_sha256 = models.CharField(max_length=64, blank=True)
    uploaded_ip_hash = models.CharField(max_length=64, blank=True)

    email_sent_at = models.DateTimeField(null=True, blank=True)
    confirmation_email_sent_at = models.DateTimeField(null=True, blank=True)
    uploaded_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    cancelled_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(
                fields=["status", "-created_at"], name="docs_status_created_idx"
            ),
            models.Index(fields=["student_name"], name="docs_student_name_idx"),
        ]

    def __str__(self) -> str:
        return f"{self.student_name} - {self.document_label}"

    @property
    def document_label(self) -> str:
        if self.document_type == self.DocumentType.OTHER:
            return self.other_document_name.strip() or "Additional supporting document"
        return self.get_document_type_display()

    @property
    def can_upload(self) -> bool:
        return self.status == self.Status.PENDING and self.expires_at > timezone.now()

    @property
    def has_file(self) -> bool:
        return bool(self.uploaded_file and self.original_filename)


class AuditEvent(models.Model):
    class Event(models.TextChoices):
        REQUEST_CREATED = "request_created", "Request created"
        REQUEST_EMAIL_SENT = "request_email_sent", "Request email sent"
        REQUEST_EMAIL_FAILED = "request_email_failed", "Request email failed"
        REQUEST_RESENT = "request_resent", "Request resent"
        DOCUMENT_UPLOADED = "document_uploaded", "Document uploaded"
        CONFIRMATION_EMAIL_SENT = "confirmation_email_sent", "Confirmation email sent"
        CONFIRMATION_EMAIL_FAILED = (
            "confirmation_email_failed",
            "Confirmation email failed",
        )
        DOCUMENT_DOWNLOADED = "document_downloaded", "Document downloaded"
        DOCUMENT_PURGED = "document_purged", "Document purged"
        REQUEST_COMPLETED = "request_completed", "Request completed"
        REQUEST_CANCELLED = "request_cancelled", "Request cancelled"
        REQUEST_EXPIRED = "request_expired", "Request expired"
        PORTAL_LOGIN = "portal_login", "Portal login"
        PORTAL_LOGIN_FAILED = "portal_login_failed", "Portal login failed"

    id = models.BigAutoField(primary_key=True)
    document_request = models.ForeignKey(
        DocumentRequest,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="audit_events",
    )
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="document_portal_audit_events",
    )
    event = models.CharField(max_length=40, choices=Event.choices, db_index=True)
    ip_hash = models.CharField(max_length=64, blank=True)
    details = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["event", "-created_at"], name="docs_audit_event_idx"),
        ]

    def __str__(self) -> str:
        return f"{self.get_event_display()} at {self.created_at:%Y-%m-%d %H:%M:%S}"
