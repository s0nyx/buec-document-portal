from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from documents.models import AuditEvent, DocumentRequest
from documents.services import record_event


class Command(BaseCommand):
    help = (
        "Delete encrypted files for completed requests older than the retention period."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--older-than-days",
            type=int,
            default=settings.DOCUMENT_RETENTION_DAYS,
            help="Purge completed uploads older than this many days.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report how many files would be removed without deleting them.",
        )

    def handle(self, *args, **options):
        days = options["older_than_days"]
        if days < 1:
            raise CommandError("--older-than-days must be at least 1.")

        cutoff = timezone.now() - timedelta(days=days)
        queryset = DocumentRequest.objects.filter(
            status=DocumentRequest.Status.COMPLETED,
            uploaded_at__lt=cutoff,
        ).exclude(uploaded_file="")

        if options["dry_run"]:
            count = queryset.count()
            self.stdout.write(f"{count} encrypted document file(s) would be purged.")
            return

        purged = 0
        for request_id in queryset.values_list("pk", flat=True).iterator(
            chunk_size=100
        ):
            with transaction.atomic():
                item = DocumentRequest.objects.select_for_update().get(pk=request_id)
                if not item.uploaded_file:
                    continue
                storage = item.uploaded_file.storage
                stored_name = item.uploaded_file.name
                details = {
                    "sha256": item.file_sha256,
                    "size": item.file_size,
                    "retention_days": days,
                }
                storage.delete(stored_name)
                item.uploaded_file = ""
                item.original_filename = ""
                item.detected_mime = ""
                item.file_size = None
                item.file_sha256 = ""
                item.uploaded_ip_hash = ""
                item.save(
                    update_fields=[
                        "uploaded_file",
                        "original_filename",
                        "detected_mime",
                        "file_size",
                        "file_sha256",
                        "uploaded_ip_hash",
                        "updated_at",
                    ]
                )
                record_event(
                    AuditEvent.Event.DOCUMENT_PURGED,
                    document_request=item,
                    details=details,
                )
                purged += 1

        self.stdout.write(
            self.style.SUCCESS(f"Purged {purged} encrypted document file(s).")
        )
