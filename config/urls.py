from django.conf import settings
from django.urls import include, path

urlpatterns = [
    path("", include("documents.urls")),
    path(
        f"{settings.ADMIN_PORTAL_SLUG}/",
        include(("documents.portal_urls", "portal"), namespace="portal"),
    ),
]

handler400 = "documents.views_public.bad_request"
handler403 = "documents.views_public.permission_denied"
handler404 = "documents.views_public.not_found"
handler500 = "documents.views_public.server_error"
