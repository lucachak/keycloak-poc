# Django + Keycloak dashboard

Aplicação Django autenticada via OpenID Connect, com uma dashboard de identidade
e autorização baseada em roles (RBAC).

## Como as roles são resolvidas

A aplicação aceita os formatos mais comuns dos dois provedores:

- Microsoft Entra ID: `roles: ["Dashboard.Reader", "Reports.Manager"]`
- Keycloak Realm Roles: `realm_access.roles`
- Keycloak Client Roles: `resource_access["django-app"].roles`

Quando um usuário tem mais de uma role, as permissões são cumulativas. Por
exemplo, `Dashboard.Reader` concede acesso de leitura à dashboard e
`Reports.Manager` acrescenta visualização e exportação de relatórios.

O catálogo, o mapa entre roles e permissões e o decorator de proteção estão em
`core/access.py`. Mapeamentos específicos do ambiente podem ser adicionados em
`config/settings.py`:

```python
RBAC_ROLE_PERMISSIONS = {
    "Minha.Role.Do.Entra": {
        "dashboard.view",
        "reports.view",
    },
}
```

Uma role desconhecida aparece na tela para diagnóstico, mas não concede nenhuma
permissão até ser mapeada explicitamente.

## Protegendo uma view

```python
from core.access import keycloak_permission_required


@keycloak_permission_required("reports.export")
def export_report(request):
    ...
```

A dashboard inclui um exemplo real em `/api/reports/export/`. Mesmo que alguém
tente chamar o endpoint diretamente, a operação retorna HTTP 403 quando o
usuário não possui `reports.export`.

## Executando

```bash
docker compose up -d --build
```

As App Roles atribuídas no Entra ID precisam estar presentes no claim `roles` do
ID token/userinfo. Se o Entra estiver conectado ao Keycloak como Identity
Provider, configure um mapper no Keycloak para preservar essas roles no token
entregue à aplicação.

## Inspecionando o mapper de roles

Em desenvolvimento, cada login compara `userinfo`, ID token e access token,
imprimindo somente os claims relacionados à autorização. Tokens e dados pessoais
não são escritos no log:

```text
OIDC mapper — claims de autorização recebidos:
{
  "userinfo": {
    "entra_app_roles": ["Dashboard.Reader", "Reports.Manager"]
  },
  "id_token": {
    "keycloak_realm_roles": ["member"]
  },
  "access_token": {
    "keycloak_client_roles": {"django-app": ["manager"]}
  }
}
```

Para acompanhar o resultado durante o login:

```bash
docker compose logs -f django
```

Se uma role aparecer em `access_token`, mas não em `userinfo`, habilite **Add to
userinfo** no mapper usado pelo client. Se aparecer no ID token, mas não no
userinfo, confira também **Add to ID token** e a configuração do client scope.

O diagnóstico é habilitado automaticamente quando `DEBUG=True`. Em outros
ambientes, ele pode ser controlado explicitamente:

```env
OIDC_LOG_ROLE_CLAIMS=false
```

## Logout OIDC

O logout encerra primeiro a sessão Django e depois redireciona o navegador para
o endpoint de RP-Initiated Logout do Keycloak. O `id_token_hint` evita uma etapa
de confirmação e o usuário retorna para `/logged-out/`.

No client `django-app`, configure em **Settings → Login settings**:

```text
Valid redirect URIs:
https://lucachak-keycloak.eastus.cloudapp.azure.com/auth/callback/

Valid post logout redirect URIs:
https://lucachak-keycloak.eastus.cloudapp.azure.com/logged-out/

Web origins:
https://lucachak-keycloak.eastus.cloudapp.azure.com
```

Para outros ambientes, cadastre a URL HTTPS correspondente. O valor precisa
coincidir exatamente com `KEYCLOAK_POST_LOGOUT_REDIRECT_URI`. Se essa variável
não for definida, a aplicação monta a URL usando o host da requisição.

Na VM, a aplicação usa estas origens públicas por padrão:

```text
Django:   https://lucachak-keycloak.eastus.cloudapp.azure.com
Keycloak: https://lucachak-keycloak.eastus.cloudapp.azure.com:8443
```

O proxy HTTPS do Django deve encaminhar `X-Forwarded-Proto: https`. Dentro da
rede Docker, o Django acessa o Keycloak por `http://keycloak:8080`; somente o
navegador usa a URL pública HTTPS na porta 8443.
