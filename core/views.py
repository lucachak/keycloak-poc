from django.http import JsonResponse
from django.shortcuts import redirect, render

from .oidc import oauth
from django.http import JsonResponse


def health(request):
    return JsonResponse({
        "status": "ok",
        "service": "django"
    })



def index(request):
    user = request.session.get("user")

    if not user:
        return redirect("/login/")

    return render(
        request,
        "core/dashboard.html",
        {
            "user": user,
        }
    )

def login_view(request):
    redirect_uri = request.build_absolute_uri(
        "/auth/callback/"
    )

    return oauth.keycloak.authorize_redirect(
        request,
        redirect_uri,
    )

def callback(request):
    token = oauth.keycloak.authorize_access_token(request)
    userinfo = token["userinfo"]
    request.session["user"] = dict(userinfo)
    return redirect("/")


def logout_view(request):

    request.session.flush()

    return redirect("/")
