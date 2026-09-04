from django.contrib import admin
from django.urls import path

from core import views


urlpatterns = [
    path("admin/", admin.site.urls),

    path("", views.index),
    path("login/", views.login_view),
    path("auth/callback/", views.callback),
    path("logout/", views.logout_view),
    path("logged-out/", views.logged_out),
    path("api/me/", views.current_user),
    path("api/reports/export/", views.export_report),
    path("health/", views.health),
    ]
