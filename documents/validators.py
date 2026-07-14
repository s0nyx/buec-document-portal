from __future__ import annotations

import io
import re
import warnings
import zipfile
from dataclasses import dataclass
from pathlib import Path

from django.conf import settings
from django.core.exceptions import ValidationError
from PIL import Image, UnidentifiedImageError
from pillow_heif import register_heif_opener

register_heif_opener()
Image.MAX_IMAGE_PIXELS = 40_000_000

ALLOWED_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".webp",
    ".heic",
    ".heif",
    ".tif",
    ".tiff",
    ".pdf",
    ".docx",
    ".odt",
    ".rtf",
    ".txt",
}

IMAGE_FORMATS = {
    ".jpg": {"JPEG"},
    ".jpeg": {"JPEG"},
    ".png": {"PNG"},
    ".webp": {"WEBP"},
    ".heic": {"HEIF", "HEIC"},
    ".heif": {"HEIF", "HEIC"},
    ".tif": {"TIFF"},
    ".tiff": {"TIFF"},
}

MIME_BY_EXTENSION = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".webp": "image/webp",
    ".heic": "image/heic",
    ".heif": "image/heif",
    ".tif": "image/tiff",
    ".tiff": "image/tiff",
    ".pdf": "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".odt": "application/vnd.oasis.opendocument.text",
    ".rtf": "application/rtf",
    ".txt": "text/plain",
}


@dataclass(frozen=True)
class ValidatedDocument:
    safe_filename: str
    extension: str
    detected_mime: str
    size: int
    plain_bytes: bytes


_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")


def _safe_filename(original_name: str) -> str:
    name = original_name.replace("\\", "/").split("/")[-1].strip()
    name = _CONTROL_CHARACTERS.sub("", name)
    if not name:
        raise ValidationError("The selected file does not have a valid name.")
    if len(name) > 220:
        stem = Path(name).stem[:180]
        suffix = Path(name).suffix[:20]
        name = f"{stem}{suffix}"
    return name


def _verify_image(data: bytes, extension: str) -> None:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as image:
                image_format = (image.format or "").upper()
                if image_format not in IMAGE_FORMATS[extension]:
                    raise ValidationError(
                        "The file extension does not match the image content."
                    )
                width, height = image.size
                if width <= 0 or height <= 0 or width * height > Image.MAX_IMAGE_PIXELS:
                    raise ValidationError("The image dimensions are not allowed.")
                image.verify()
    except ValidationError:
        raise
    except (
        UnidentifiedImageError,
        OSError,
        SyntaxError,
        Image.DecompressionBombWarning,
    ) as exc:
        raise ValidationError(
            "The image is damaged or not a supported image file."
        ) from exc


def _validate_zip_safety(archive: zipfile.ZipFile) -> set[str]:
    infos = archive.infolist()
    if len(infos) > 1000:
        raise ValidationError("The document archive contains too many files.")

    total_uncompressed = 0
    names: set[str] = set()
    for info in infos:
        name = info.filename.replace("\\", "/")
        names.add(name)
        if name.startswith("/") or ".." in Path(name).parts:
            raise ValidationError("The document archive contains an unsafe path.")
        if info.flag_bits & 0x1:
            raise ValidationError(
                "Password-protected document archives are not supported."
            )
        total_uncompressed += info.file_size
        if total_uncompressed > 100 * 1024 * 1024:
            raise ValidationError("The document archive expands to an unsafe size.")
        if info.file_size > 1_000_000 and info.compress_size == 0:
            raise ValidationError(
                "The document archive has an unsafe compression ratio."
            )
        if info.compress_size and info.file_size / info.compress_size > 250:
            raise ValidationError(
                "The document archive has an unsafe compression ratio."
            )

    if archive.testzip() is not None:
        raise ValidationError("The document archive is damaged.")
    return names


def _verify_docx(data: bytes) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = _validate_zip_safety(archive)
            required = {"[Content_Types].xml", "_rels/.rels", "word/document.xml"}
            if not required.issubset(names):
                raise ValidationError("The file is not a valid DOCX document.")
            if any(name.lower().endswith("vbaproject.bin") for name in names):
                raise ValidationError(
                    "Macro-enabled Office documents are not accepted."
                )
    except ValidationError:
        raise
    except (zipfile.BadZipFile, OSError) as exc:
        raise ValidationError("The DOCX document is damaged or invalid.") from exc


def _verify_odt(data: bytes) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = _validate_zip_safety(archive)
            if "mimetype" not in names or "content.xml" not in names:
                raise ValidationError("The file is not a valid ODT document.")
            mimetype = archive.read("mimetype")[:100]
            if mimetype != b"application/vnd.oasis.opendocument.text":
                raise ValidationError("The file is not a valid ODT document.")
    except ValidationError:
        raise
    except (zipfile.BadZipFile, KeyError, OSError) as exc:
        raise ValidationError("The ODT document is damaged or invalid.") from exc


def _verify_pdf(data: bytes) -> None:
    if not data.startswith(b"%PDF-") or b"%%EOF" not in data[-8192:]:
        raise ValidationError(
            "The PDF is damaged or does not contain a valid PDF signature."
        )


def _verify_rtf(data: bytes) -> None:
    if not data.lstrip().startswith(b"{\\rtf"):
        raise ValidationError("The file is not a valid RTF document.")


def _verify_text(data: bytes) -> None:
    if b"\x00" in data[:4096]:
        # UTF-16 text legitimately contains NUL bytes, so try it before rejecting.
        for encoding in ("utf-16", "utf-16-le", "utf-16-be"):
            try:
                data.decode(encoding)
                return
            except UnicodeDecodeError:
                continue
        raise ValidationError("The text document contains unsupported binary data.")
    try:
        data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValidationError(
            "Text documents must use UTF-8 or UTF-16 encoding."
        ) from exc


def validate_uploaded_document(uploaded_file) -> ValidatedDocument:
    if not uploaded_file:
        raise ValidationError("Choose a document to upload.")

    safe_name = _safe_filename(uploaded_file.name)
    extension = Path(safe_name).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise ValidationError(
            "Unsupported file type. Use JPG, JPEG, PNG, WEBP, HEIC, HEIF, TIFF, PDF, "
            "DOCX, ODT, RTF, or TXT."
        )

    size = int(getattr(uploaded_file, "size", 0) or 0)
    if size <= 0:
        raise ValidationError("The selected file is empty.")
    if size > settings.MAX_UPLOAD_SIZE_BYTES:
        raise ValidationError(
            f"The file is too large. The maximum size is {settings.MAX_UPLOAD_SIZE_MB} MB."
        )

    uploaded_file.seek(0)
    data = uploaded_file.read(settings.MAX_UPLOAD_SIZE_BYTES + 1)
    uploaded_file.seek(0)
    if len(data) != size:
        size = len(data)
    if len(data) > settings.MAX_UPLOAD_SIZE_BYTES:
        raise ValidationError(
            f"The file is too large. The maximum size is {settings.MAX_UPLOAD_SIZE_MB} MB."
        )

    if extension in IMAGE_FORMATS:
        _verify_image(data, extension)
    elif extension == ".pdf":
        _verify_pdf(data)
    elif extension == ".docx":
        _verify_docx(data)
    elif extension == ".odt":
        _verify_odt(data)
    elif extension == ".rtf":
        _verify_rtf(data)
    elif extension == ".txt":
        _verify_text(data)

    return ValidatedDocument(
        safe_filename=safe_name,
        extension=extension,
        detected_mime=MIME_BY_EXTENSION[extension],
        size=len(data),
        plain_bytes=data,
    )
