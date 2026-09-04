import logging
from datetime import datetime, timezone
from urllib.parse import urlencode

from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import redirect, render

from .access import (
    access_summary,
    keycloak_permission_required,
    token_role_diagnostics,
)
from .oidc import CLIENT_ID, PUBLIC_URL, REALM, oauth


logger = logging.getLogger("core.oidc")


def app_public_url(request, path):
    if settings.APP_PUBLIC_URL:
        return f"{settings.APP_PUBLIC_URL}/{path.lstrip('/')}"
    return request.build_absolute_uri(path)


def health(request):
    return JsonResponse({"status": "ok", "service": "django"})


def index(request):
    user = request.session.get("user")

    if not user:
        return redirect("/login/")

    # Older sessions may only contain Keycloak's preferred_username claim.
    user = dict(user)
    user.setdefault("username", user.get("preferred_username"))

    access = access_summary(user)
    visible_roles = [role["name"] for role in access["roles"]]

    authenticated_at = request.session.get("authenticated_at")
    if authenticated_at:
        try:
            login_time = datetime.fromisoformat(authenticated_at).astimezone()
            last_login = login_time.strftime("%d/%m/%Y, %H:%M")
        except (TypeError, ValueError):
            last_login = "Sessão atual"
    else:
        last_login = "Sessão atual"

    return render(request, "core/dashboard.html", {
        "user": user,
        "roles": visible_roles or ["Sem role"],
        "access": access,
        "last_login": last_login,
        "keycloak_account_url": f"{PUBLIC_URL}/realms/{REALM}/account/",
        "keycloak_realm": REALM,
        "activities": [
            {
                "kind": "login",
                "title": "Login realizado com sucesso",
                "detail": "Autenticação OpenID Connect via Keycloak",
                "time": "Agora",
                "status": "Sucesso",
            },
            {
                "kind": "security",
                "title": "Token de acesso emitido",
                "detail": "Escopos: openid, profile e email",
                "time": "Agora",
                "status": "Protegido",
            },
            {
                "kind": "profile",
                "title": "Perfil sincronizado",
                "detail": "Dados de identidade atualizados pelo provedor",
                "time": "Hoje, 09:41",
                "status": "Sincronizado",
            },
            {
                "kind": "app",
                "title": "Aplicação acessada",
                "detail": "Dashboard Django",
                "time": "Ontem, 16:28",
                "status": "Concluído",
            },
        ],
    })


def login_view(request):
    redirect_uri = app_public_url(request, "/auth/callback/")

    return oauth.keycloak.authorize_redirect(
        request,
        redirect_uri,
    )

def callback(request):
    token = oauth.keycloak.authorize_access_token(request)
    userinfo = dict(token["userinfo"])
    userinfo.setdefault("username", userinfo.get("preferred_username"))

    request.session.cycle_key()
    request.session["user"] = userinfo
    request.session["authenticated_at"] = datetime.now(timezone.utc).isoformat()

    # necessário para RP-Initiated Logout
    if token.get("id_token"):
        request.session["id_token"] = token["id_token"]

    return redirect("/")

def logout_view(request):
    id_token = request.session.get("id_token")

    post_logout_redirect_uri = (
        settings.OIDC_POST_LOGOUT_REDIRECT_URI
        or app_public_url(request, "/logged-out/")
    )
    params = {
        "post_logout_redirect_uri": post_logout_redirect_uri,
        "client_id": CLIENT_ID,
    }

    if id_token:
        params["id_token_hint"] = id_token

    # The ID token must be read before flush(), which rotates the Django session.
    request.session.flush()

    logout_url = (
        f"{PUBLIC_URL.rstrip('/')}"
        f"/realms/{REALM}"
        "/protocol/openid-connect/logout?"
        + urlencode(params)
    )

    return redirect(logout_url)


def logged_out(request):
    request.session.flush()
    return render(request, "core/logged_out.html")


@keycloak_permission_required("reports.export")
def export_report(request):
    """Small protected action used by the dashboard to demonstrate RBAC."""
    response = JsonResponse({
        "status": "ready",
        "generated_by": request.session["user"].get("preferred_username"),
        "report": "Resumo de acessos",
        "rows": 24,
    })
    response["Content-Disposition"] = 'attachment; filename="relatorio-acessos.json"'
    return response
