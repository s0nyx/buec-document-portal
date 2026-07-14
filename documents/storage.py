from __future__ import annotations

import uuid

from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.utils import timezone
from django.utils.deconstruct import deconstructible


@deconstructible
class PrivateUploadStorage(FileSystemStorage):
    def __init__(self) -> None:
        super().__init__(
            location=settings.PRIVATE_UPLOAD_ROOT,
            base_url=None,
            file_permissions_mode=0o600,
            directory_permissions_mode=0o700,
        )


private_upload_storage = PrivateUploadStorage()


def private_upload_path(instance, filename: str) -> str:
    now = timezone.now()
    return f"{now:%Y/%m}/{uuid.uuid4().hex}.bin"
