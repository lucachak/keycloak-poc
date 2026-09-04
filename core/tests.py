import os
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from django.http import HttpResponse
from django.test import SimpleTestCase, TestCase, override_settings

from .access import (
    decode_jwt_payload_for_diagnostics,
    effective_permissions,
    extract_roles,
    role_claim_diagnostics,
)


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

        response = self.client.get("/logout/")
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

        response = self.client.get("/logout/")
        query = parse_qs(urlparse(response.url).query)

        self.assertNotIn("id_token_hint", query)
        self.assertEqual(query["client_id"], ["django"])

    @override_settings(
        OIDC_POST_LOGOUT_REDIRECT_URI="https://app.example.com/logged-out/",
    )
    def test_logout_can_use_configured_public_redirect_uri(self):
        response = self.client.get("/logout/")
        query = parse_qs(urlparse(response.url).query)

        self.assertEqual(
            query["post_logout_redirect_uri"],
            ["https://app.example.com/logged-out/"],
        )

    def test_logged_out_page_is_public(self):
        response = self.client.get("/logged-out/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Sessão encerrada")
