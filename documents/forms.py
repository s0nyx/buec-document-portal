from __future__ import annotations

from django import forms
from django.contrib.auth.forms import AuthenticationForm

from .malware import scan_document_for_malware
from .models import DocumentRequest
from .validators import ValidatedDocument, validate_uploaded_document


class StyledAuthenticationForm(AuthenticationForm):
    username = forms.CharField(
        max_length=150,
        widget=forms.TextInput(
            attrs={
                "autocomplete": "username",
                "class": "form-control",
                "placeholder": "Username",
            }
        ),
    )
    password = forms.CharField(
        strip=False,
        widget=forms.PasswordInput(
            attrs={
                "autocomplete": "current-password",
                "class": "form-control",
                "placeholder": "Password",
            }
        ),
    )


class NewDocumentRequestForm(forms.Form):
    student_name = forms.CharField(
        max_length=160,
        strip=True,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "autocomplete": "name",
                "placeholder": "e.g. Amelia Smith",
            }
        ),
    )
    student_email = forms.EmailField(
        max_length=254,
        widget=forms.EmailInput(
            attrs={
                "class": "form-control",
                "autocomplete": "email",
                "placeholder": "student@example.com",
            }
        ),
    )
    document_type = forms.ChoiceField(
        choices=DocumentRequest.DocumentType.choices,
        widget=forms.Select(
            attrs={"class": "form-control", "data-document-type": "true"}
        ),
    )
    other_document_name = forms.CharField(
        max_length=160,
        required=False,
        strip=True,
        widget=forms.TextInput(
            attrs={
                "class": "form-control",
                "placeholder": "Optional description, e.g. bank statement",
                "data-other-document": "true",
            }
        ),
    )

    def clean_student_name(self) -> str:
        value = " ".join(self.cleaned_data["student_name"].split())
        if len(value) < 2:
            raise forms.ValidationError("Enter the student's full name.")
        return value

    def clean_student_email(self) -> str:
        return self.cleaned_data["student_email"].strip().lower()


class UploadDocumentForm(forms.Form):
    document = forms.FileField(
        widget=forms.ClearableFileInput(
            attrs={
                "class": "file-input",
                "accept": ".jpg,.jpeg,.png,.webp,.heic,.heif,.tif,.tiff,.pdf,.docx,.odt,.rtf,.txt",
                "data-upload-input": "true",
            }
        )
    )
    website = forms.CharField(required=False, widget=forms.HiddenInput())

    validated_document: ValidatedDocument | None = None

    def clean_website(self) -> str:
        value = self.cleaned_data.get("website", "")
        if value:
            raise forms.ValidationError("Unable to process this upload.")
        return value

    def clean_document(self):
        uploaded = self.cleaned_data["document"]
        self.validated_document = validate_uploaded_document(uploaded)
        scan_document_for_malware(self.validated_document.plain_bytes)
        return uploaded
