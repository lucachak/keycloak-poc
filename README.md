# Orbit — Django + Keycloak

Aplicação Django autenticada por OpenID Connect, com autorização baseada em
roles (RBAC), dashboards específicos por perfil e atualização automática dos
acessos durante a sessão.

A interface usa uma direção visual editorial e responsiva: landing page
pública, central de identidade, visualização de roles e permissões, timeline de
atividades, workspaces por role e uma tela dedicada para o encerramento da
sessão.

## Funcionalidades

- login SSO pelo Keycloak usando Authorization Code Flow;
- validação criptográfica do access token com o JWKS do realm;
- suporte a Keycloak Realm Roles, Client Roles e Microsoft Entra App Roles;
- conversão de roles em permissões efetivas no backend;
- dashboards separados para `viewer`, `analyst`, `pentester` e `admin`;
- grupos OIDC disponíveis na interface e na API;
- atualização automática de roles e grupos a cada 15 segundos;
- logout local e RP-Initiated Logout no Keycloak;
- endpoints protegidos por role ou permissão;
- interface responsiva para desktop e dispositivos móveis.

## Arquitetura do fluxo

```text
Navegador
   │
   ├── GET /login/ ───────────────► Keycloak público :8443
   │                                  │
   │◄──────── authorization code ─────┘
   │
   ├── GET /auth/callback/ ───────► Django
   │                                  │
   │                                  ├── troca o code pelo token
   │                                  ├── valida assinatura e claims
   │                                  ├── consulta userinfo
   │                                  └── salva identidade na sessão
   │
   ├── POST /api/session/sync/ ───► refresh token no servidor
   │
   └── POST /logout/ ─────────────► logout no Keycloak
                                      └── /logged-out/
```

O navegador recebe somente o cookie da sessão Django. Access token, ID token e
refresh token não são devolvidos ao JavaScript.

## Endereços do ambiente Azure

```text
Aplicação Django:
https://lucachak-keycloak.eastus.cloudapp.azure.com

Keycloak:
https://lucachak-keycloak.eastus.cloudapp.azure.com:8443

Realm:
lab

Client:
django-app
```

Dentro da rede Docker, o Django acessa o Keycloak em
`http://keycloak:8080`. O navegador usa sempre a URL pública HTTPS na porta
`8443`.

## Pré-requisitos

- Docker e Docker Compose;
- DNS apontando para a VM;
- HTTPS configurado para a aplicação e para o Keycloak;
- client confidencial criado no Keycloak;
- portas públicas e regras de firewall configuradas na VM/Azure.

## Variáveis de ambiente

Crie um arquivo `.env` na raiz do projeto:

```env
APP_PUBLIC_URL=https://lucachak-keycloak.eastus.cloudapp.azure.com
DJANGO_ALLOWED_HOSTS=lucachak-keycloak.eastus.cloudapp.azure.com,localhost,127.0.0.1
DJANGO_CSRF_TRUSTED_ORIGINS=https://lucachak-keycloak.eastus.cloudapp.azure.com
DJANGO_SECRET_KEY=troque-por-uma-chave-forte-e-aleatoria
DJANGO_DEBUG=true

KEYCLOAK_PUBLIC_URL=https://lucachak-keycloak.eastus.cloudapp.azure.com:8443
KEYCLOAK_INTERNAL_URL=http://keycloak:8080
KEYCLOAK_REALM=lab
KEYCLOAK_CLIENT_ID=django-app
KEYCLOAK_CLIENT_SECRET=cole-aqui-o-secret-do-client
KEYCLOAK_POST_LOGOUT_REDIRECT_URI=https://lucachak-keycloak.eastus.cloudapp.azure.com/logged-out/

OIDC_LOG_ROLE_CLAIMS=true
```

Em produção, use `DJANGO_DEBUG=false`, armazene os secrets fora do repositório e
sirva os arquivos estáticos pelo proxy ou por uma solução como WhiteNoise.

## Configuração do client no Keycloak

Crie ou edite o client `django-app` no realm `lab`.

Configuração recomendada:

```text
Client type: OpenID Connect
Client authentication: On
Standard flow: On
Direct access grants: Off
```

Em **Settings → Login settings**, configure exatamente:

```text
Root URL:
https://lucachak-keycloak.eastus.cloudapp.azure.com

Home URL:
https://lucachak-keycloak.eastus.cloudapp.azure.com/

Valid redirect URIs:
https://lucachak-keycloak.eastus.cloudapp.azure.com/auth/callback/

Valid post logout redirect URIs:
https://lucachak-keycloak.eastus.cloudapp.azure.com/logged-out/

Web origins:
https://lucachak-keycloak.eastus.cloudapp.azure.com
```

Depois, copie o secret disponível em **Credentials** para
`KEYCLOAK_CLIENT_SECRET`.

As URLs devem coincidir exatamente, incluindo protocolo, porta e barra final.
Evite `*` nas redirect URIs de produção.

## Configuração de roles e grupos

As roles utilizadas pela aplicação são Client Roles do client `django-app`:

| Role | Permissões efetivas |
| --- | --- |
| `viewer` | dashboard, perfil e atividades |
| `analyst` | recursos de viewer e visualização de relatórios |
| `pentester` | recursos de analyst e exportação de relatórios |
| `admin` | todas as permissões, incluindo usuários |

Elas podem ser atribuídas diretamente ao usuário ou herdadas por grupos:

1. crie as roles em **Clients → django-app → Roles**;
2. crie os grupos em **Groups**;
3. associe as Client Roles aos grupos;
4. adicione o usuário ao grupo correspondente.

### Mapper de Client Roles

No client scope aplicado ao `django-app`, crie ou confira o mapper de Client
Roles. Habilite:

```text
Add to access token: On
Add to ID token: On
Add to userinfo: On
```

O formato esperado no access token é:

```json
{
  "resource_access": {
    "django-app": {
      "roles": ["viewer", "analyst"]
    }
  }
}
```

### Mapper de grupos

Crie um mapper do tipo **Group Membership** e configure:

```text
Token claim name: groups
Full group path: On
Add to access token: On
Add to ID token: On
Add to userinfo: On
```

Os grupos serão recebidos no claim:

```json
{
  "groups": ["/security", "/administrators"]
}
```

## Como as roles são resolvidas

A aplicação consolida roles provenientes de três estruturas:

- Microsoft Entra ID App Roles: `roles`;
- Keycloak Realm Roles: `realm_access.roles`;
- Keycloak Client Roles: `resource_access["django-app"].roles`.

Roles internas do provedor, como `offline_access`, `uma_authorization` e
`default-roles-lab`, são ignoradas. Client roles de outras aplicações também
não concedem acesso ao Django.

Quando o usuário possui várias roles, as permissões são cumulativas. A role
`admin` usa `*` e recebe todo o catálogo de permissões.

O catálogo e a resolução estão em `core/access.py`. Mapeamentos adicionais
podem ser definidos em `config/settings.py`:

```python
RBAC_ROLE_PERMISSIONS = {
    "Minha.Role": {
        "dashboard.view",
        "reports.view",
    },
}
```

Uma role desconhecida aparece para diagnóstico, mas não concede permissões até
ser explicitamente mapeada.

## Protegendo views no Django

Por permissão:

```python
from core.access import keycloak_permission_required


@keycloak_permission_required("reports.export")
def export_report(request):
    ...
```

Por role exata:

```python
from core.access import keycloak_role_required


@keycloak_role_required("admin")
def admin_workspace(request):
    ...
```

Esconder um link na interface não é considerado autorização. Todas as rotas
sensíveis validam novamente a sessão no backend e retornam HTTP 403 quando o
acesso não é permitido.

## Dashboards e endpoints

| Rota | Descrição | Proteção |
| --- | --- | --- |
| `/` | landing pública ou central autenticada | pública |
| `/login/` | inicia o login no Keycloak | pública |
| `/auth/callback/` | callback OIDC | state + code |
| `/dashboards/viewer/` | workspace Viewer | role `viewer` |
| `/dashboards/analyst/` | workspace Analyst | role `analyst` |
| `/dashboards/pentester/` | workspace Pentester | role `pentester` |
| `/dashboards/admin/` | workspace Admin | role `admin` |
| `/api/me/` | identidade e acessos atuais | sessão Django |
| `/api/session/sync/` | atualiza roles e grupos | sessão + refresh token |
| `/api/reports/export/` | exemplo de exportação | `reports.export` |
| `/logout/` | inicia logout local e OIDC | `POST` + CSRF |
| `/logged-out/` | confirmação de logout | pública |
| `/health/` | saúde do serviço | pública |

Exemplo de `/api/me/`:

```json
{
  "user": {
    "sub": "5a249e01-cc60-4ede-8eaa-2b3eb6f6d556",
    "username": "lucas",
    "name": "Lucas Lucachak",
    "email": "lucachak@proton.me"
  },
  "roles": ["viewer", "pentester", "admin", "analyst"],
  "groups": ["/security", "/administrators"],
  "permissions": [
    "activity.view",
    "dashboard.view",
    "profile.view",
    "reports.export",
    "reports.view",
    "users.manage"
  ]
}
```

## Atualização automática de acessos

Enquanto uma área autenticada está aberta, `core/static/core/session_sync.js`
faz `POST /api/session/sync/` a cada 15 segundos.

O backend usa o refresh token guardado na sessão para:

1. solicitar tokens atualizados ao Keycloak;
2. validar novamente o access token;
3. consultar o endpoint `userinfo`;
4. substituir as roles e grupos antigos pelos claims atuais;
5. recalcular as permissões;
6. avisar a interface quando houve mudança.

Se roles ou grupos mudarem, a página é recarregada automaticamente. Se o
refresh token expirar, a sessão local é removida e o usuário volta ao login.

## Logout OIDC

A rota `/logout/` aceita somente `POST` e exige um token CSRF válido. O fluxo:

1. recupera o `id_token_hint` antes de limpar a sessão;
2. remove a sessão Django;
3. redireciona para o endpoint de logout do realm;
4. envia `client_id`, `id_token_hint` e `post_logout_redirect_uri`;
5. retorna para `/logged-out/`.

Se o Keycloak mostrar **Invalid redirect uri**, confira se a URL abaixo está em
**Valid post logout redirect URIs**:

```text
https://lucachak-keycloak.eastus.cloudapp.azure.com/logged-out/
```

## Executando com Docker

```bash
docker compose up -d --build
```

Acompanhe os serviços:

```bash
docker compose ps
docker compose logs -f django
docker compose logs -f keycloak
```

Aplicação exposta diretamente pelo Compose:

```text
Django:   http://localhost:8000
Keycloak: http://localhost:8081
```

As URLs públicas continuam sendo definidas pelas variáveis de ambiente. Em uma
VM, normalmente o proxy HTTPS recebe as conexões públicas e as encaminha para
essas portas locais.

## Reverse proxy na VM Azure

O proxy da aplicação deve preservar o host e informar o protocolo original:

```text
Host: lucachak-keycloak.eastus.cloudapp.azure.com
X-Forwarded-Proto: https
X-Forwarded-For: endereço do cliente
```

O Django usa `SECURE_PROXY_SSL_HEADER` e `APP_PUBLIC_URL` para nunca gerar um
callback HTTP atrás do terminador TLS.

O Keycloak está configurado com:

```text
KC_PROXY_HEADERS=xforwarded
KC_HTTP_ENABLED=true
KC_HOSTNAME=https://lucachak-keycloak.eastus.cloudapp.azure.com:8443
```

## Diagnóstico dos claims

Quando `OIDC_LOG_ROLE_CLAIMS=true`, cada login compara as informações de
autorização presentes em userinfo, ID token e access token. Tokens completos e
dados pessoais não são escritos no log.

```bash
docker compose logs -f django
```

Exemplo resumido:

```text
OIDC roles recebidas:
{
  "access_token": {
    "groups": ["/security"],
    "keycloak_client_roles": {
      "django-app": ["viewer", "pentester"]
    },
    "resolved_application_roles": ["viewer", "pentester"]
  }
}
```

Por padrão, somente assinaturas `RS256` são aceitas. Algoritmos adicionais
precisam ser declarados explicitamente:

```env
KEYCLOAK_SIGNING_ALGORITHMS=RS256
```

## Interface

Os arquivos principais da experiência visual são:

```text
core/templates/core/public.html
core/templates/core/dashboard.html
core/templates/core/role_dashboard.html
core/templates/core/logged_out.html
core/static/core/orbit.css
core/static/core/dashboard.js
core/static/core/session_sync.js
```

O frontend permanece server-rendered pelo Django, com CSS responsivo e
JavaScript progressivo, sem incluir tokens OIDC no estado do navegador.

## Testes

Com as variáveis do Keycloak definidas:

```bash
python manage.py test
```

A suíte cobre resolução de roles, validação do access token, callback OIDC,
sincronização de sessão, API de identidade, autorização dos dashboards e
logout.

## Problemas comuns

### `unauthorized_client: Invalid client or Invalid client credentials`

- confirme que `Client authentication` está habilitado;
- copie novamente o secret em **Clients → django-app → Credentials**;
- confira `KEYCLOAK_CLIENT_ID` e `KEYCLOAK_CLIENT_SECRET` no container Django;
- recrie o container depois de alterar o `.env`.

### A role aparece no log, mas não na API

- confirme que ela pertence ao client `django-app`;
- habilite os três destinos do mapper: access token, ID token e userinfo;
- confirme que o grupo possui a Client Role e que o usuário pertence ao grupo;
- faça logout e login novamente para obter o primeiro refresh token da sessão.

### O perfil não atualiza depois de alterar uma role

- aguarde até 15 segundos;
- confira se a sessão possui refresh token;
- inspecione `POST /api/session/sync/` no navegador;
- confirme que o novo access token contém a role;
- verifique os logs do Django e do Keycloak.

### Callback gerado com `http://`

- defina `APP_PUBLIC_URL` com a origem HTTPS;
- encaminhe `X-Forwarded-Proto: https` no proxy;
- confira `DJANGO_CSRF_TRUSTED_ORIGINS`.

### `Invalid redirect uri` durante o logout

- cadastre a URL em **Valid post logout redirect URIs**;
- mantenha a barra final;
- confira `KEYCLOAK_POST_LOGOUT_REDIRECT_URI`;
- não use a URL do Keycloak como redirect de retorno da aplicação.
