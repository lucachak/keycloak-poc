import os
import time
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import requests
from django.http import HttpResponse
from django.test import Client, SimpleTestCase, TestCase, override_settings
from joserfc import jwt
from joserfc.jwk import RSAKey

from .access import (
    decode_jwt_payload_for_diagnostics,
    effective_permissions,
    extract_roles,
    role_claim_diagnostics,
)
from .oidc import CLIENT_ID, ISSUER, verified_access_token_claims


@override_settings(
    OIDC_CLIENT_ID="django-app",
    OIDC_POST_LOGOUT_REDIRECT_URI=None,
)
class RoleResolutionTests(SimpleTestCase):
    def test_combines_two_entra_app_roles(self):
        claims = {"roles": ["Dashboard.Reader", "Reports.Manager"]}

        permissions = effective_permissions(claims)

        self.assertIn("dashboard.view", permissions)
        self.assertIn("reports.export", permissions)

    def test_pentester_can_access_reports_but_not_manage_users(self):
        permissions = effective_permissions({"roles": ["pentester"]})

        self.assertIn("dashboard.view", permissions)
        self.assertIn("reports.view", permissions)
        self.assertIn("reports.export", permissions)
        self.assertNotIn("users.manage", permissions)

    def test_admin_receives_every_catalog_permission(self):
        permissions = effective_permissions({"roles": ["admin"]})

        self.assertIn("reports.export", permissions)
        self.assertIn("users.manage", permissions)

    def test_combines_keycloak_realm_and_current_client_roles(self):
        claims = {
            "realm_access": {"roles": ["viewer", "offline_access"]},
            "resource_access": {
                "django-app": {"roles": ["manager"]},
                "another-app": {"roles": ["admin"]},
            },
        }

        self.assertEqual(extract_roles(claims), ["viewer", "manager"])
        self.assertNotIn("users.manage", effective_permissions(claims))

    def test_diagnostics_contains_roles_but_not_unrelated_claims(self):
        claims = {
            "email": "private@example.com",
            "roles": ["Dashboard.Reader"],
            "resource_access": {"django-app": {"roles": ["manager"]}},
        }

        diagnostics = role_claim_diagnostics(claims)

        self.assertEqual(diagnostics["entra_app_roles"], ["Dashboard.Reader"])
        self.assertEqual(diagnostics["keycloak_client_roles"]["django-app"], ["manager"])
        self.assertNotIn("email", diagnostics)

    def test_invalid_diagnostic_token_is_ignored(self):
        self.assertEqual(decode_jwt_payload_for_diagnostics("not-a-jwt"), {})

    @patch("core.oidc.oauth.keycloak.fetch_jwk_set")
    def test_verifies_roles_from_access_token(self, fetch_jwk_set):
        key = RSAKey.generate_key(auto_kid=True)
        fetch_jwk_set.return_value = {"keys": [key.as_dict(private=False)]}
        encoded_token = jwt.encode(
            {"alg": "RS256", "kid": key.kid},
            {
                "iss": ISSUER,
                "sub": "user-123",
                "azp": CLIENT_ID,
                "exp": int(time.time()) + 300,
                "resource_access": {
                    CLIENT_ID: {"roles": ["pentester"]},
                },
            },
            key,
            algorithms=["RS256"],
        )

        claims = verified_access_token_claims({"access_token": encoded_token})

        self.assertEqual(extract_roles(claims), ["pentester"])

    @patch("core.oidc.oauth.keycloak.fetch_jwk_set")
    def test_rejects_access_token_from_another_client(self, fetch_jwk_set):
        key = RSAKey.generate_key(auto_kid=True)
        fetch_jwk_set.return_value = {"keys": [key.as_dict(private=False)]}
        encoded_token = jwt.encode(
            {"alg": "RS256", "kid": key.kid},
            {
                "iss": ISSUER,
                "sub": "user-123",
                "azp": "another-client",
                "aud": "account",
                "exp": int(time.time()) + 300,
            },
            key,
            algorithms=["RS256"],
        )

        with self.assertRaisesRegex(ValueError, "not issued to this client"):
            verified_access_token_claims({"access_token": encoded_token})


@override_settings(
    APP_PUBLIC_URL="",
    OIDC_POST_LOGOUT_REDIRECT_URI=None,
)
class DashboardViewTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = patch.dict(os.environ, {
            "KEYCLOAK_PUBLIC_URL": "http://localhost:8080",
            "KEYCLOAK_INTERNAL_URL": "http://keycloak:8080",
            "KEYCLOAK_REALM": "demo",
            "KEYCLOAK_CLIENT_ID": "django",
            "KEYCLOAK_CLIENT_SECRET": "test-secret",
        })
        cls.env.start()
        cls.public_url = patch("core.views.PUBLIC_URL", "http://localhost:8080")
        cls.realm = patch("core.views.REALM", "demo")
        cls.client_id = patch("core.views.CLIENT_ID", "django")
        cls.public_url.start()
        cls.realm.start()
        cls.client_id.start()
        super().setUpClass()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        cls.client_id.stop()
        cls.realm.stop()
        cls.public_url.stop()
        cls.env.stop()

    def test_anonymous_user_is_redirected_to_login(self):
        response = self.client.get("/")
        self.assertRedirects(response, "/login/", fetch_redirect_response=False)

    @override_settings(APP_PUBLIC_URL="https://app.example.com")
    def test_login_uses_configured_public_callback_uri(self):
        with patch("core.views.oauth.keycloak.authorize_redirect") as authorize:
            authorize.return_value = HttpResponse(status=302)

            response = self.client.get("/login/")

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            authorize.call_args.args[1],
            "https://app.example.com/auth/callback/",
        )

    def test_authenticated_user_sees_oidc_dashboard(self):
        session = self.client.session
        session["user"] = {
            "name": "Lucas Silva",
            "given_name": "Lucas",
            "preferred_username": "lucas",
            "email": "lucas@example.com",
            "email_verified": True,
            "sub": "user-123",
            "iss": "http://localhost:8080/realms/demo",
            "aud": "django",
            "realm_access": {"roles": ["member", "offline_access"]},
        }
        session.save()

        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Olá, Lucas")
        self.assertContains(response, "Keycloak")
        self.assertContains(response, "Centro de atividades")
        self.assertContains(response, "Member")

    @override_settings(OIDC_LOG_ROLE_CLAIMS=False)
    @patch("core.views.verified_access_token_claims")
    @patch("core.views.oauth.keycloak.userinfo")
    @patch("core.views.oauth.keycloak.authorize_access_token")
    def test_callback_stores_verified_roles(
        self,
        authorize_access_token,
        fetch_userinfo,
        access_token_claims,
    ):
        authorize_access_token.return_value = {
            "id_token": "header.payload.signature",
            "refresh_token": "refresh-token",
            "userinfo": {
                "sub": "user-123",
                "preferred_username": "lucas",
                "realm_access": {"roles": ["viewer"]},
            },
        }
        fetch_userinfo.return_value = {
            "sub": "user-123",
            "preferred_username": "lucas",
            "email": "lucas@example.com",
            "groups": ["/security"],
            "resource_access": {
                "django": {"roles": ["manager"]},
            },
        }
        access_token_claims.return_value = {
            "groups": ["/security", "/operations"],
            "resource_access": {
                "django": {"roles": ["pentester"]},
            },
        }

        response = self.client.get("/auth/callback/")

        self.assertRedirects(response, "/", fetch_redirect_response=False)
        self.assertEqual(
            self.client.session["user"]["roles"],
            ["viewer", "manager", "pentester"],
        )
        self.assertEqual(
            self.client.session["user"]["groups"],
            ["/security", "/operations"],
        )
        self.assertEqual(
            self.client.session["id_token"],
            "header.payload.signature",
        )
        self.assertEqual(self.client.session["refresh_token"], "refresh-token")

    def test_current_user_api_returns_roles_and_permissions(self):
        session = self.client.session
        session["user"] = {
            "sub": "user-123",
            "preferred_username": "lucas",
            "email": "lucas@example.com",
            "groups": ["/security"],
            "resource_access": {
                "django-app": {"roles": ["manager"]},
            },
        }
        session.save()

        response = self.client.get("/api/me/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["roles"], ["manager"])
        self.assertEqual(response.json()["groups"], ["/security"])
        self.assertIn("reports.export", response.json()["permissions"])

    def test_current_user_api_requires_authentication(self):
        response = self.client.get("/api/me/")

        self.assertEqual(response.status_code, 401)

    @override_settings(OIDC_LOG_ROLE_CLAIMS=False)
    @patch("core.views.oauth.keycloak.userinfo")
    @patch("core.views.verified_access_token_claims")
    @patch("core.views.refresh_keycloak_token")
    def test_sync_identity_updates_roles_and_groups(
        self,
        refresh_token,
        access_token_claims,
        fetch_userinfo,
    ):
        session = self.client.session
        session["user"] = {
            "sub": "user-123",
            "preferred_username": "lucas",
            "roles": ["viewer"],
            "groups": ["/readers"],
        }
        session["refresh_token"] = "old-refresh-token"
        session.save()
        refresh_token.return_value = {
            "access_token": "new-access-token",
            "refresh_token": "new-refresh-token",
            "id_token": "new-id-token",
        }
        access_token_claims.return_value = {
            "sub": "user-123",
            "resource_access": {
                "django": {"roles": ["pentester", "admin"]},
            },
            "groups": ["/security"],
        }
        fetch_userinfo.return_value = {
            "sub": "user-123",
            "preferred_username": "lucas",
        }

        response = self.client.post("/api/session/sync/")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["changed"])
        self.assertEqual(response.json()["roles"], ["pentester", "admin"])
        self.assertEqual(response.json()["groups"], ["/security"])
        self.assertEqual(
            self.client.session["refresh_token"],
            "new-refresh-token",
        )
        self.assertEqual(self.client.session["id_token"], "new-id-token")

    def test_sync_identity_requires_refresh_token(self):
        session = self.client.session
        session["user"] = {
            "sub": "user-123",
            "preferred_username": "lucas",
            "roles": ["viewer"],
        }
        session.save()

        response = self.client.post("/api/session/sync/")

        self.assertEqual(response.status_code, 409)

    @patch("core.views.refresh_keycloak_token")
    def test_sync_identity_clears_expired_session(self, refresh_token):
        session = self.client.session
        session["user"] = {"sub": "user-123", "roles": ["viewer"]}
        session["refresh_token"] = "expired-refresh-token"
        session.save()
        http_response = requests.Response()
        http_response.status_code = 400
        refresh_token.side_effect = requests.HTTPError(response=http_response)

        response = self.client.post("/api/session/sync/")

        self.assertEqual(response.status_code, 401)
        self.assertNotIn("user", self.client.session)

    def test_user_can_open_each_assigned_role_dashboard(self):
        session = self.client.session
        session["user"] = {
            "name": "Lucas",
            "preferred_username": "lucas",
            "roles": ["viewer", "analyst", "pentester", "admin"],
            "groups": ["/security", "/administrators"],
        }
        session.save()

        for role in ("viewer", "analyst", "pentester", "admin"):
            with self.subTest(role=role):
                response = self.client.get(f"/dashboards/{role}/")
                self.assertEqual(response.status_code, 200)
                self.assertContains(response, f"Dashboard {role.title()}")

    def test_role_dashboard_rejects_user_without_required_role(self):
        session = self.client.session
        session["user"] = {
            "preferred_username": "lucas",
            "roles": ["viewer"],
        }
        session.save()

        response = self.client.get("/dashboards/admin/")

        self.assertEqual(response.status_code, 403)

    def test_role_dashboard_redirects_anonymous_user_to_login(self):
        response = self.client.get("/dashboards/viewer/")

        self.assertRedirects(response, "/login/", fetch_redirect_response=False)

    def test_export_requires_reports_export_permission(self):
        session = self.client.session
        session["user"] = {"preferred_username": "lucas", "roles": ["Dashboard.Reader"]}
        session.save()

        response = self.client.get("/api/reports/export/")

        self.assertEqual(response.status_code, 403)

    def test_two_roles_can_unlock_export_permission(self):
        session = self.client.session
        session["user"] = {
            "preferred_username": "lucas",
            "roles": ["Dashboard.Reader", "Reports.Manager"],
        }
        session.save()

        response = self.client.get("/api/reports/export/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ready")

    def test_logout_clears_session_and_redirects_to_keycloak(self):
        session = self.client.session
        session["user"] = {"preferred_username": "lucas"}
        session["id_token"] = "header.payload.signature"
        session.save()

        response = self.client.post("/logout/")
        redirect_url = urlparse(response.url)
        query = parse_qs(redirect_url.query)

        self.assertEqual(response.status_code, 302)
        self.assertEqual(redirect_url.netloc, "localhost:8080")
        self.assertTrue(redirect_url.path.startswith("/realms/demo/"))
        self.assertTrue(redirect_url.path.endswith("/protocol/openid-connect/logout"))
        self.assertEqual(query["id_token_hint"], ["header.payload.signature"])
        self.assertEqual(query["client_id"], ["django"])
        self.assertEqual(query["post_logout_redirect_uri"], ["http://testserver/logged-out/"])
        self.assertNotIn("user", self.client.session)

    def test_logout_without_id_token_uses_client_id(self):
        session = self.client.session
        session["user"] = {"preferred_username": "lucas"}
        session.save()

        response = self.client.post("/logout/")
        query = parse_qs(urlparse(response.url).query)

        self.assertNotIn("id_token_hint", query)
        self.assertEqual(query["client_id"], ["django"])

    @override_settings(
        OIDC_POST_LOGOUT_REDIRECT_URI="https://app.example.com/logged-out/",
    )
    def test_logout_can_use_configured_public_redirect_uri(self):
        response = self.client.post("/logout/")
        query = parse_qs(urlparse(response.url).query)

        self.assertEqual(
            query["post_logout_redirect_uri"],
            ["https://app.example.com/logged-out/"],
        )

    def test_logout_rejects_get_requests(self):
        response = self.client.get("/logout/")

        self.assertEqual(response.status_code, 405)

    def test_logout_post_requires_csrf_token(self):
        csrf_client = Client(enforce_csrf_checks=True)

        response = csrf_client.post("/logout/")

        self.assertEqual(response.status_code, 403)

    def test_logged_out_page_is_public(self):
        response = self.client.get("/logged-out/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Sessão encerrada")
