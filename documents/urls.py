from django.urls import path

from . import views_public

urlpatterns = [
    path("", views_public.home, name="home"),
    path("upload/success/", views_public.upload_success, name="upload-success"),
    path("upload/<str:token>/", views_public.upload_document, name="document-upload"),
    path("robots.txt", views_public.robots, name="robots"),
]
