import base64
import json
from functools import wraps

from django.conf import settings
from django.http import HttpResponseForbidden
from django.shortcuts import redirect


PERMISSION_CATALOG = {
    "dashboard.view": {
        "label": "Visualizar dashboard",
        "description": "Acessar indicadores e o resumo da conta.",
        "group": "Workspace",
    },
    "profile.view": {
        "label": "Visualizar perfil",
        "description": "Consultar os próprios dados de identidade.",
        "group": "Identidade",
    },
    "activity.view": {
        "label": "Visualizar atividades",
        "description": "Consultar o histórico recente de acessos.",
        "group": "Auditoria",
    },
    "reports.view": {
        "label": "Visualizar relatórios",
        "description": "Consultar relatórios disponíveis no workspace.",
        "group": "Relatórios",
    },
    "reports.export": {
        "label": "Exportar relatórios",
        "description": "Gerar e baixar exportações de relatórios.",
        "group": "Relatórios",
    },
    "users.manage": {
        "label": "Gerenciar usuários",
        "description": "Administrar acessos e usuários da aplicação.",
        "group": "Administração",
    },
}


DEFAULT_ROLE_PERMISSIONS = {
    # Roles simples, úteis para Keycloak.
    "member": {"dashboard.view", "profile.view"},
    "viewer": {"dashboard.view", "profile.view", "activity.view"},
    "analyst": {"dashboard.view", "profile.view", "activity.view", "reports.view"},
    "pentester": {
        "dashboard.view", "profile.view", "activity.view",
        "reports.view", "reports.export",
    },
    "manager": {
        "dashboard.view", "profile.view", "activity.view",
        "reports.view", "reports.export",
    },
    "admin": {"*"},
    # App Roles com nomenclatura comum no Microsoft Entra ID.
    "dashboard.reader": {"dashboard.view", "profile.view", "activity.view"},
    "reports.manager": {"reports.view", "reports.export"},
    "user.administrator": {"*"},
}

IGNORED_PROVIDER_ROLES = {"offline_access", "uma_authorization"}


def _as_role_list(value):
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [role for role in value if isinstance(role, str)]
    return []


def extract_roles(claims, client_id=None):
    """Collect roles from Entra ID and Keycloak without trusting other clients."""
    claims = claims or {}
    roles = []

    # Microsoft Entra ID app roles.
    roles.extend(_as_role_list(claims.get("roles")))

    # Keycloak realm roles.
    roles.extend(_as_role_list(claims.get("realm_access", {}).get("roles")))

    # Keycloak roles scoped to this application only.
    client_id = client_id or getattr(settings, "OIDC_CLIENT_ID", None)
    if client_id:
        client_roles = claims.get("resource_access", {}).get(client_id, {}).get("roles")
        roles.extend(_as_role_list(client_roles))

    # Preserve the provider spelling while deduplicating case-insensitively.
    unique_roles = {}
    for role in roles:
        clean_role = role.strip()
        normalized = clean_role.casefold()
        is_provider_default = (
            normalized in IGNORED_PROVIDER_ROLES
            or normalized.startswith("default-roles-")
        )
        if clean_role and not is_provider_default:
            unique_roles.setdefault(clean_role.casefold(), clean_role)
    return list(unique_roles.values())


def extract_groups(claims):
    """Return normalized group paths received from the identity provider."""
    unique_groups = {}
    for group in _as_role_list((claims or {}).get("groups")):
        clean_group = group.strip()
        if clean_group:
            unique_groups.setdefault(clean_group.casefold(), clean_group)
    return list(unique_groups.values())


def role_permissions():
    configured = getattr(settings, "RBAC_ROLE_PERMISSIONS", {})
    merged = {role: set(permissions) for role, permissions in DEFAULT_ROLE_PERMISSIONS.items()}
    for role, permissions in configured.items():
        merged[role.casefold()] = set(permissions)
    return merged


def effective_permissions(claims, client_id=None):
    permissions = set()
    mapping = role_permissions()

    for role in extract_roles(claims, client_id):
        permissions.update(mapping.get(role.casefold(), set()))

    if "*" in permissions:
        return set(PERMISSION_CATALOG)
    return permissions


def has_permission(claims, permission, client_id=None):
    return permission in effective_permissions(claims, client_id)


def role_claim_diagnostics(claims, client_id=None):
    """Return only authorization-related claims, safe for development logs."""
    claims = claims or {}
    resource_access = {}

    for resource, access in claims.get("resource_access", {}).items():
        if isinstance(access, dict):
            resource_access[resource] = _as_role_list(access.get("roles"))

    return {
        "issuer": claims.get("iss"),
        "audience": claims.get("aud"),
        "entra_app_roles": _as_role_list(claims.get("roles")),
        "groups": _as_role_list(claims.get("groups")),
        "keycloak_realm_roles": _as_role_list(
            claims.get("realm_access", {}).get("roles")
        ),
        "keycloak_client_roles": resource_access,
        "resolved_application_roles": extract_roles(claims, client_id),
        "effective_permissions": sorted(effective_permissions(claims, client_id)),
    }


def decode_jwt_payload_for_diagnostics(encoded_token):
    """Decode a JWT payload for logging only; never use this for authorization."""
    if not isinstance(encoded_token, str):
        return {}
    try:
        payload = encoded_token.split(".")[1]
        padding = "=" * (-len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload + padding)
        claims = json.loads(decoded)
        return claims if isinstance(claims, dict) else {}
    except (IndexError, ValueError, TypeError, json.JSONDecodeError):
        return {}


def token_role_diagnostics(token_response, client_id=None):
    """Compare role claims across userinfo, ID token and access token."""
    token_response = token_response or {}
    return {
        "userinfo": role_claim_diagnostics(
            token_response.get("userinfo", {}), client_id
        ),
        "id_token": role_claim_diagnostics(
            decode_jwt_payload_for_diagnostics(token_response.get("id_token")),
            client_id,
        ),
        "access_token": role_claim_diagnostics(
            decode_jwt_payload_for_diagnostics(token_response.get("access_token")),
            client_id,
        ),
    }


def access_summary(claims, client_id=None):
    roles = extract_roles(claims, client_id)
    mapping = role_permissions()
    permissions = effective_permissions(claims, client_id)

    role_items = []
    for role in roles:
        role_permission_codes = mapping.get(role.casefold(), set())
        if "*" in role_permission_codes:
            role_permission_codes = set(PERMISSION_CATALOG)
        role_items.append({
            "name": role,
            "known": role.casefold() in mapping,
            "permissions": [
                {"code": code, **PERMISSION_CATALOG[code]}
                for code in sorted(role_permission_codes)
                if code in PERMISSION_CATALOG
            ],
        })

    return {
        "roles": role_items,
        "role_count": len(roles),
        "permissions": [
            {"code": code, **PERMISSION_CATALOG[code]}
            for code in sorted(permissions)
        ],
        "permission_count": len(permissions),
        "can_export_reports": "reports.export" in permissions,
        "is_admin": "users.manage" in permissions,
    }


def keycloak_permission_required(permission):
    """Protect a Django view using the verified claims stored in the session."""
    def decorator(view_function):
        @wraps(view_function)
        def wrapped(request, *args, **kwargs):
            claims = request.session.get("user")
            if not claims:
                return redirect("/login/")
            if not has_permission(claims, permission):
                return HttpResponseForbidden("Você não possui permissão para esta ação.")
            return view_function(request, *args, **kwargs)
        return wrapped
    return decorator


def keycloak_role_required(required_role):
    """Protect a view with an exact application role from verified claims."""
    def decorator(view_function):
        @wraps(view_function)
        def wrapped(request, *args, **kwargs):
            claims = request.session.get("user")
            if not claims:
                return redirect("/login/")
            roles = {role.casefold() for role in extract_roles(claims)}
            if required_role.casefold() not in roles:
                return HttpResponseForbidden(
                    f"A role {required_role} é necessária para acessar esta área."
                )
            return view_function(request, *args, **kwargs)
        return wrapped
    return decorator
