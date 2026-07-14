from django.urls import path

from . import views_portal

urlpatterns = [
    path("", views_portal.dashboard, name="dashboard"),
    path("login/", views_portal.portal_login, name="login"),
    path("logout/", views_portal.portal_logout, name="logout"),
    path("requests/table/", views_portal.request_table, name="request-table"),
    path("requests/new/", views_portal.create_request, name="request-create"),
    path(
        "requests/<uuid:request_id>/resend/",
        views_portal.resend_request,
        name="request-resend",
    ),
    path(
        "requests/<uuid:request_id>/complete/",
        views_portal.complete_request,
        name="request-complete",
    ),
    path(
        "requests/<uuid:request_id>/cancel/",
        views_portal.cancel_request,
        name="request-cancel",
    ),
    path(
        "requests/<uuid:request_id>/download/",
        views_portal.download_document,
        name="request-download",
    ),
]
