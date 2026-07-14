from django.conf import settings


def brand(request):
    return {
        "brand_name": settings.BRAND_NAME,
        "brand_short_name": settings.BRAND_SHORT_NAME,
        "support_email": settings.SUPPORT_EMAIL,
        "support_phone": settings.SUPPORT_PHONE,
        "max_upload_size_mb": settings.MAX_UPLOAD_SIZE_MB,
        "upload_token_lifetime_days": settings.UPLOAD_TOKEN_LIFETIME_DAYS,
    }
