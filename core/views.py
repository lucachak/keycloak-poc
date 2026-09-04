import json
import logging
from datetime import datetime, timezone
from urllib.parse import urlencode

import requests
from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_POST
from joserfc.errors import JoseError

from .access import (
    access_summary,
    extract_groups,
    extract_roles,
    keycloak_permission_required,
    keycloak_role_required,
    token_role_diagnostics,
)
from .oidc import (
    CLIENT_ID,
    PUBLIC_URL,
    REALM,
    oauth,
    refresh_keycloak_token,
    verified_access_token_claims,
)


logger = logging.getLogger("core.oidc")


ROLE_DASHBOARDS = {
    "viewer": {
        "label": "Viewer",
        "kicker": "Leitura e acompanhamento",
        "description": "Uma visão objetiva da identidade, dos acessos e das atividades disponíveis para consulta.",
        "accent": "blue",
        "sections": [
            {"title": "Visão geral", "description": "Consulte o estado atual da conta e da sessão autenticada.", "permission": "dashboard.view"},
            {"title": "Perfil", "description": "Visualize os dados sincronizados pelo Keycloak.", "permission": "profile.view"},
            {"title": "Atividades", "description": "Acompanhe os eventos recentes associados ao workspace.", "permission": "activity.view"},
        ],
    },
    "analyst": {
        "label": "Analyst",
        "kicker": "Análise e inteligência",
        "description": "Espaço para consultar relatórios, acompanhar tendências e transformar dados de acesso em contexto.",
        "accent": "violet",
        "sections": [
            {"title": "Painel analítico", "description": "Organize indicadores e leituras relevantes para a operação.", "permission": "dashboard.view"},
            {"title": "Relatórios", "description": "Consulte os relatórios disponibilizados para análise.", "permission": "reports.view"},
            {"title": "Trilha de atividades", "description": "Correlacione eventos recentes para apoiar investigações.", "permission": "activity.view"},
        ],
    },
    "pentester": {
        "label": "Pentester",
        "kicker": "Security workspace",
        "description": "Área técnica para organizar evidências, revisar superfícies autorizadas e exportar resultados.",
        "accent": "amber",
        "sections": [
            {"title": "Escopo autorizado", "description": "Centralize os recursos liberados para as avaliações de segurança.", "permission": "dashboard.view"},
            {"title": "Evidências", "description": "Consulte achados e informações de suporte aos testes.", "permission": "reports.view"},
            {"title": "Exportações", "description": "Exporte o resumo de acessos para documentação e auditoria.", "permission": "reports.export"},
        ],
    },
    "admin": {
        "label": "Admin",
        "kicker": "Governança e administração",
        "description": "Controle central de usuários, roles, permissões e integridade do ambiente autenticado.",
        "accent": "rose",
        "sections": [
            {"title": "Usuários", "description": "Administre identidades e acompanhe os acessos concedidos.", "permission": "users.manage"},
            {"title": "Governança de roles", "description": "Revise como roles se transformam em permissões efetivas.", "permission": "users.manage"},
            {"title": "Auditoria", "description": "Acompanhe atividades e eventos relevantes do workspace.", "permission": "activity.view"},
        ],
    },
}


def app_public_url(request, path):
    if settings.APP_PUBLIC_URL:
        return f"{settings.APP_PUBLIC_URL}/{path.lstrip('/')}"
    return request.build_absolute_uri(path)


def health(request):
    return JsonResponse({"status": "ok", "service": "django"})


def available_role_areas(claims):
    assigned = {role.casefold() for role in extract_roles(claims)}
    return [
        {
            "slug": slug,
            "url": f"/dashboards/{slug}/",
            **definition,
        }
        for slug, definition in ROLE_DASHBOARDS.items()
        if slug in assigned
    ]


def merge_identity_claims(identity_sources, entitlement_sources, base=None):
    """Build session identity while replacing, not accumulating, entitlements."""
    userinfo = dict(base or {})
    userinfo.pop("roles", None)
    userinfo.pop("groups", None)

    for source in identity_sources:
        userinfo.update(source or {})

    resolved_roles = []
    seen_roles = set()
    resolved_groups = []
    seen_groups = set()
    for source in entitlement_sources:
        for role in extract_roles(source, CLIENT_ID):
            if role.casefold() not in seen_roles:
                resolved_roles.append(role)
                seen_roles.add(role.casefold())
        for group in extract_groups(source):
            if group.casefold() not in seen_groups:
                resolved_groups.append(group)
                seen_groups.add(group.casefold())

    userinfo["roles"] = resolved_roles
    userinfo["groups"] = resolved_groups
    userinfo.setdefault("username", userinfo.get("preferred_username"))
    return userinfo


@never_cache
def index(request):
    user = request.session.get("user")

    if not user:
        return render(request, "core/public.html")

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
        "groups": extract_groups(user),
        "role_areas": available_role_areas(user),
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
    id_token_claims = dict(token.get("userinfo") or {})
    endpoint_claims = dict(oauth.keycloak.userinfo(token=token))
    access_token_claims = verified_access_token_claims(token)

    # Both sources are verified by Authlib/Keycloak. Keep canonical role/group
    # lists so the rest of the application does not depend on token layout.
    userinfo = merge_identity_claims(
        (id_token_claims, endpoint_claims),
        (id_token_claims, endpoint_claims, access_token_claims),
    )

    if settings.OIDC_LOG_ROLE_CLAIMS:
        diagnostic_token = {**token, "userinfo": endpoint_claims}
        logger.info(
            "OIDC roles recebidas:\n%s",
            json.dumps(
                token_role_diagnostics(diagnostic_token, CLIENT_ID),
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            ),
        )

    request.session.cycle_key()
    request.session["user"] = userinfo
    request.session["authenticated_at"] = datetime.now(timezone.utc).isoformat()
    if token.get("refresh_token"):
        request.session["refresh_token"] = token["refresh_token"]

    # necessário para RP-Initiated Logout
    if token.get("id_token"):
        request.session["id_token"] = token["id_token"]

    return redirect("/")


@require_POST
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


def render_role_dashboard(request, role):
    claims = dict(request.session["user"])
    claims.setdefault("username", claims.get("preferred_username"))
    access = access_summary(claims)
    definition = ROLE_DASHBOARDS[role]
    effective_codes = {
        permission["code"] for permission in access["permissions"]
    }
    sections = [
        {**section, "enabled": section["permission"] in effective_codes}
        for section in definition["sections"]
    ]
    return render(request, "core/role_dashboard.html", {
        "user": claims,
        "role_slug": role,
        "role_dashboard": {**definition, "sections": sections},
        "role_areas": available_role_areas(claims),
        "access": access,
        "groups": extract_groups(claims),
        "keycloak_account_url": f"{PUBLIC_URL}/realms/{REALM}/account/",
    })


@never_cache
@keycloak_role_required("viewer")
def viewer_dashboard(request):
    return render_role_dashboard(request, "viewer")


@never_cache
@keycloak_role_required("analyst")
def analyst_dashboard(request):
    return render_role_dashboard(request, "analyst")


@never_cache
@keycloak_role_required("pentester")
def pentester_dashboard(request):
    return render_role_dashboard(request, "pentester")


@never_cache
@keycloak_role_required("admin")
def admin_dashboard(request):
    return render_role_dashboard(request, "admin")


@never_cache
def current_user(request):
    claims = request.session.get("user")
    if not claims:
        return JsonResponse({"detail": "Não autenticado."}, status=401)

    access = access_summary(claims)
    return JsonResponse({
        "user": {
            "sub": claims.get("sub"),
            "username": claims.get("preferred_username") or claims.get("username"),
            "name": claims.get("name"),
            "email": claims.get("email"),
        },
        "roles": [role["name"] for role in access["roles"]],
        "groups": extract_groups(claims),
        "permissions": [
            permission["code"] for permission in access["permissions"]
        ],
    })


@never_cache
@require_POST
def sync_identity(request):
    current_claims = request.session.get("user")
    refresh_token = request.session.get("refresh_token")
    if not current_claims:
        return JsonResponse({"detail": "Não autenticado."}, status=401)
    if not refresh_token:
        return JsonResponse({
            "detail": "Sessão sem refresh token; faça login novamente.",
        }, status=409)

    try:
        token = refresh_keycloak_token(refresh_token)
        access_token_claims = verified_access_token_claims(token)
        endpoint_claims = dict(oauth.keycloak.userinfo(token=token))
    except requests.HTTPError as error:
        status_code = getattr(error.response, "status_code", None)
        logger.warning("Keycloak recusou a sincronização OIDC: HTTP %s", status_code)
        if status_code in {400, 401}:
            request.session.flush()
            return JsonResponse({"detail": "Sessão expirada."}, status=401)
        return JsonResponse({"detail": "Não foi possível sincronizar."}, status=502)
    except (requests.RequestException, JoseError, ValueError) as error:
        logger.warning("Falha ao sincronizar identidade OIDC: %s", error)
        return JsonResponse({"detail": "Não foi possível sincronizar."}, status=502)

    if access_token_claims.get("sub") != current_claims.get("sub"):
        logger.error("Refresh token retornou uma identidade diferente da sessão.")
        request.session.flush()
        return JsonResponse({"detail": "Sessão inválida."}, status=401)

    updated_claims = merge_identity_claims(
        (endpoint_claims,),
        (endpoint_claims, access_token_claims),
        base=current_claims,
    )
    old_roles = extract_roles(current_claims, CLIENT_ID)
    old_groups = extract_groups(current_claims)
    new_roles = extract_roles(updated_claims, CLIENT_ID)
    new_groups = extract_groups(updated_claims)
    changed = old_roles != new_roles or old_groups != new_groups

    request.session["user"] = updated_claims
    request.session["refresh_token"] = token.get("refresh_token", refresh_token)
    if token.get("id_token"):
        request.session["id_token"] = token["id_token"]
    request.session["roles_synced_at"] = datetime.now(timezone.utc).isoformat()

    access = access_summary(updated_claims)
    return JsonResponse({
        "changed": changed,
        "roles": new_roles,
        "groups": new_groups,
        "permissions": [item["code"] for item in access["permissions"]],
    })


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
