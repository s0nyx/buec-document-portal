from django.core.management.base import BaseCommand

from documents.services import expire_stale_document_requests


class Command(BaseCommand):
    help = (
        "Expire pending document requests whose single-use link has passed its expiry."
    )

    def handle(self, *args, **options):
        expired_count = expire_stale_document_requests()
        self.stdout.write(
            self.style.SUCCESS(f"Expired {expired_count} document request(s).")
        )
