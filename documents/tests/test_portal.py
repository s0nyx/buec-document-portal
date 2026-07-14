from __future__ import annotations

import io
import re
import shutil
from datetime import timedelta
from pathlib import Path

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core import mail
from django.core.management import call_command
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from PIL import Image

from documents.crypto import issue_upload_token
from documents.models import AuditEvent, DocumentRequest


@override_settings(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    PUBLIC_BASE_URL="https://documents.example.test",
)
class DocumentPortalFlowTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        user_model = get_user_model()
        cls.superuser = user_model.objects.create_superuser(
            username="owner",
            email="owner@example.test",
            password="A-strong-test-password-729!",
        )
        cls.staff_user = user_model.objects.create_user(
            username="staff",
            email="staff@example.test",
            password="Another-strong-password-729!",
            is_staff=True,
        )

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        shutil.rmtree(settings.PRIVATE_UPLOAD_ROOT, ignore_errors=True)

    def _jpeg_upload(self, filename: str = "passport.jpg") -> SimpleUploadedFile:
        output = io.BytesIO()
        Image.new("RGB", (16, 16), (245, 245, 245)).save(output, format="JPEG")
        return SimpleUploadedFile(
            filename, output.getvalue(), content_type="image/jpeg"
        )

    def _pending_request(self, **overrides):
        token = issue_upload_token()
        values = {
            "student_name": "Amelia Smith",
            "student_email": "amelia@example.test",
            "document_type": DocumentRequest.DocumentType.PASSPORT,
            "requested_by": self.superuser,
            "token_digest": token.digest,
            "token_created_at": timezone.now(),
            "expires_at": timezone.now() + timedelta(days=14),
        }
        values.update(overrides)
        return DocumentRequest.objects.create(**values), token.raw

    def test_non_superuser_cannot_access_portal(self):
        self.client.force_login(self.staff_user)
        response = self.client.get(reverse("portal:dashboard"))
        self.assertEqual(response.status_code, 403)

    def test_anonymous_portal_request_redirects_to_secret_login(self):
        response = self.client.get(reverse("portal:dashboard"))
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("portal:login"), response.url)

    def test_admin_can_create_request_and_email_contains_single_use_link(self):
        self.client.force_login(self.superuser)
        response = self.client.post(
            reverse("portal:request-create"),
            {
                "student_name": "Amelia Smith",
                "student_email": "AMELIA@EXAMPLE.TEST",
                "document_type": DocumentRequest.DocumentType.PROOF_OF_ADDRESS,
                "other_document_name": "",
            },
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(response.status_code, 201)
        payload = response.json()
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["email_sent"])

        request_item = DocumentRequest.objects.get()
        self.assertEqual(request_item.requested_by, self.superuser)
        self.assertEqual(request_item.student_email, "amelia@example.test")
        self.assertEqual(request_item.status, DocumentRequest.Status.PENDING)
        self.assertEqual(request_item.email_status, DocumentRequest.EmailStatus.SENT)
        self.assertEqual(len(mail.outbox), 1)

        match = re.search(
            r"https://documents\.example\.test/upload/([A-Za-z0-9_-]+)/",
            mail.outbox[0].body,
        )
        self.assertIsNotNone(match)
        raw_token = match.group(1)
        self.assertNotEqual(raw_token, request_item.token_digest)
        self.assertNotIn(raw_token, request_item.token_digest)

    def test_email_and_dashboard_escape_student_supplied_html(self):
        self.client.force_login(self.superuser)
        malicious_name = "<script>alert(1)</script> Student"
        response = self.client.post(
            reverse("portal:request-create"),
            {
                "student_name": malicious_name,
                "student_email": "safe@example.test",
                "document_type": DocumentRequest.DocumentType.OTHER,
                "other_document_name": "<img src=x onerror=alert(2)>",
            },
            HTTP_ACCEPT="application/json",
        )
        self.assertEqual(response.status_code, 201)
        html_email = mail.outbox[0].alternatives[0].content
        self.assertNotIn("<script>alert(1)</script>", html_email)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html_email)
        self.assertNotIn("<img src=x", html_email)

        dashboard = self.client.get(reverse("portal:dashboard"))
        self.assertNotContains(dashboard, "<script>alert(1)</script>", html=True)
        self.assertContains(dashboard, "&lt;script&gt;alert(1)&lt;/script&gt;")

    def test_valid_upload_is_encrypted_and_link_becomes_inactive(self):
        request_item, raw_token = self._pending_request()
        response = self.client.post(
            reverse("document-upload", kwargs={"token": raw_token}),
            {"document": self._jpeg_upload(), "website": ""},
        )
        self.assertRedirects(response, reverse("upload-success"))

        request_item.refresh_from_db()
        self.assertEqual(request_item.status, DocumentRequest.Status.ACTION_REQUIRED)
        self.assertTrue(request_item.has_file)
        self.assertEqual(request_item.original_filename, "passport.jpg")
        self.assertEqual(request_item.detected_mime, "image/jpeg")
        self.assertEqual(len(request_item.file_sha256), 64)
        self.assertEqual(len(mail.outbox), 1)

        request_item.uploaded_file.open("rb")
        encrypted = request_item.uploaded_file.read()
        request_item.uploaded_file.close()
        self.assertFalse(encrypted.startswith(b"\xff\xd8\xff"))
        self.assertNotIn(b"JFIF", encrypted)

        second_response = self.client.get(
            reverse("document-upload", kwargs={"token": raw_token})
        )
        self.assertEqual(second_response.status_code, 200)
        self.assertContains(second_response, "This upload link is no longer active")

    def test_unsupported_upload_is_rejected_without_consuming_link(self):
        request_item, raw_token = self._pending_request()
        upload = SimpleUploadedFile(
            "dangerous.html",
            b"<script>alert(1)</script>",
            content_type="text/html",
        )
        response = self.client.post(
            reverse("document-upload", kwargs={"token": raw_token}),
            {"document": upload, "website": ""},
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Unsupported file type")
        request_item.refresh_from_db()
        self.assertEqual(request_item.status, DocumentRequest.Status.PENDING)
        self.assertFalse(request_item.has_file)

    def test_expired_link_is_closed(self):
        request_item, raw_token = self._pending_request(
            expires_at=timezone.now() - timedelta(minutes=1)
        )
        response = self.client.get(
            reverse("document-upload", kwargs={"token": raw_token})
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "This upload link is no longer active")
        request_item.refresh_from_db()
        self.assertEqual(request_item.status, DocumentRequest.Status.EXPIRED)

    def test_authorised_download_returns_attachment_and_plain_file(self):
        request_item, raw_token = self._pending_request()
        self.client.post(
            reverse("document-upload", kwargs={"token": raw_token}),
            {"document": self._jpeg_upload("identity.jpeg"), "website": ""},
        )
        request_item.refresh_from_db()

        anonymous = self.client.get(
            reverse("portal:request-download", kwargs={"request_id": request_item.pk})
        )
        self.assertEqual(anonymous.status_code, 302)

        self.client.force_login(self.superuser)
        response = self.client.get(
            reverse("portal:request-download", kwargs={"request_id": request_item.pk})
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("attachment", response.headers["Content-Disposition"])
        self.assertIn("identity.jpeg", response.headers["Content-Disposition"])
        downloaded = b"".join(response.streaming_content)
        self.assertTrue(downloaded.startswith(b"\xff\xd8\xff"))
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")

    def test_security_headers_block_referrers_and_inline_script_sources(self):
        response = self.client.get(reverse("home"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Referrer-Policy"], "no-referrer")
        policy = response.headers["Content-Security-Policy"]
        self.assertIn("script-src 'self'", policy)
        self.assertIn("object-src 'none'", policy)
        self.assertIn("frame-ancestors 'none'", policy)

    def test_retention_command_removes_completed_encrypted_file(self):
        request_item, raw_token = self._pending_request()
        self.client.post(
            reverse("document-upload", kwargs={"token": raw_token}),
            {"document": self._jpeg_upload("retention.jpg"), "website": ""},
        )
        request_item.refresh_from_db()
        stored_path = Path(request_item.uploaded_file.path)
        self.assertTrue(stored_path.exists())

        old_date = timezone.now() - timedelta(days=120)
        DocumentRequest.objects.filter(pk=request_item.pk).update(
            status=DocumentRequest.Status.COMPLETED,
            uploaded_at=old_date,
            completed_at=old_date,
        )
        call_command("purge_completed_documents", older_than_days=90, verbosity=0)

        request_item.refresh_from_db()
        self.assertFalse(request_item.has_file)
        self.assertFalse(stored_path.exists())
        self.assertTrue(
            AuditEvent.objects.filter(
                document_request=request_item,
                event=AuditEvent.Event.DOCUMENT_PURGED,
            ).exists()
        )

    def test_search_and_action_filter_return_only_matching_rows(self):
        self._pending_request(
            student_name="Pending Person", student_email="pending@example.test"
        )
        action_item, _ = self._pending_request(
            student_name="Action Person",
            student_email="action@example.test",
            status=DocumentRequest.Status.ACTION_REQUIRED,
        )
        self.client.force_login(self.superuser)
        response = self.client.get(
            reverse("portal:request-table"),
            {"q": "Action", "status": "action"},
        )
        self.assertContains(response, "Action Person")
        self.assertNotContains(response, "Pending Person")
        self.assertEqual(list(response.context["page_obj"].object_list), [action_item])
