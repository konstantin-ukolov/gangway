# Gangway

Gangway — веб-приложение для OIDC-аутентификации пользователей Kubernetes и
самостоятельной настройки доступа через `kubectl`, Lens и другие OIDC-клиенты.

Проект основан на оригинальном [VMware Heptio Gangway](https://github.com/heptiolabs/gangway).
Upstream-проект больше не развивается активно, поэтому этот репозиторий содержит
совместимое с оригинальной концепцией, но существенно переработанное приложение.

## Что изменено в этой версии

### Server-side sessions

Браузер получает только непрозрачную cookie:

```text
gangway_session=<random session id>
```

OAuth state, ID token, refresh token и CSRF-токен logout хранятся в потокобезопасном
in-memory session store внутри процесса Gangway. Токены не записываются в cookie.

Особенности текущей реализации:

- TTL сессии с момента создания — 8 часов по умолчанию;
- TTL OAuth state — 10 минут по умолчанию;
- максимальное количество сессий — 10000 по умолчанию;
- при достижении лимита вытесняется сессия с ближайшим сроком истечения;
- истёкшие сессии очищаются периодически;
- при рестарте pod все web-сессии очищаются;
- текущая конфигурация рассчитана на одну replica.

### Совместимый kubeconfig

После успешной аутентификации Gangway генерирует стандартный kubeconfig с legacy
OIDC `auth-provider`:

```yaml
users:
  - name: user@cluster
    user:
      auth-provider:
        name: oidc
        config:
          client-id: ...
          client-secret: ...
          id-token: ...
          idp-issuer-url: ...
          refresh-token: ...
```

Такой формат подходит клиентам, которые поддерживают legacy `auth-provider: oidc`.
Современные версии `kubectl`, Lens и других клиентов могут требовать другой способ
получения OIDC-токена — совместимость нужно проверять для конкретной версии клиента.
Дополнительные локальные утилиты, exec-plugin и `ExecCredential` для поддерживаемых
legacy-клиентов не требуются.
Скачанный kubeconfig содержит чувствительные данные. Его нельзя помещать в Git,
чаты, тикеты, общие резервные копии или другие неконтролируемые хранилища.

### HTTP и OAuth hardening

- logout выполняется только через `POST`;
- logout защищён server-side CSRF-токеном;
- OAuth state сверяется с сессией и проверяется на истечение срока действия;
- добавлены `/livez`, `/readyz` и совместимый `/healthz`;
- для главной страницы, login и callback добавлены security headers,
  включая `X-Frame-Options`, `Permissions-Policy` и HSTS;
- скачивание kubeconfig помечено как `no-store` и защищено отдельной CSP;
- на UI отображается только allowlist стандартных OIDC claims;
- ошибки чтения и разбора шаблонов возвращаются без деталей файловой системы.

`/livez` проверяет доступность HTTP-сервера, `/readyz` — наличие session store.
Эти endpoints не проверяют доступность OIDC-провайдера или Kubernetes API.

### Пользовательский интерфейс

- русский и английский языки;
- светлая и тёмная темы;
- отображение срока действия ID token и оставшегося времени;
- команды настройки для shell и PowerShell;
- настройка названия приложения, компании и логотипа.

Выход из Gangway удаляет web-сессию, но не отзывает токены в уже скачанном
kubeconfig. Срок действия web-сессии и токенов определяется независимо.

### Архитектура приложения

Runtime-зависимости собраны в структуре `App`:

```go
type App struct {
    Config        *config.Config
    OAuth2Config  *oauth2.Config
    Token         oidc.OAuth2Token
    Sessions      *session.MemoryStore
    Transport     *config.TransportConfig
    OIDCVerifier  *coreosoidc.IDTokenVerifier
    VerifyIDToken func(context.Context, string) (map[string]interface{}, error)
}
```

Обработчики получают конфигурацию, OIDC verifier и session store через `App`, а не
через набор разрозненных runtime-глобальных переменных.

## Как работает flow

1. Пользователь открывает Gangway и запускает OIDC login.
2. Gangway создаёт server-side session и сохраняет OAuth state в памяти.
3. Пользователь проходит аутентификацию у внешнего OIDC-провайдера.
4. Провайдер возвращает authorization code на `/callback`.
5. Gangway проверяет state, обменивает code на токены и сохраняет их в session store.
6. Пользователь получает страницу с командами и ссылку на kubeconfig.
7. `kubectl` или Lens используют ID token и refresh token из kubeconfig.
8. Kubernetes API server проверяет OIDC token и применяет RBAC по username/groups.

Пароли пользователя не передаются Gangway: аутентификация выполняется внешним
OIDC-провайдером.

## Конфигурация

Основные поля конфигурации:

```yaml
host: 0.0.0.0
port: 8080
clusterName: example-cluster
appName: Gangway
issuerURL: https://issuer.example
authorizeURL: https://issuer.example/auth
tokenURL: https://issuer.example/token
clientID: kubernetes-oidc
redirectURL: https://gangway.example/callback
scopes: [openid, profile, email, groups, offline_access]
usernameClaim: email
apiServerURL: https://kubernetes.example:6443
clusterCAPath: /etc/gangway/cluster-ca/ca.crt
trustedCAPath: /etc/gangway/ca/ca.crt
sessionTTLHours: 8
sessionMaxCount: 10000
oauthStateTTLMinutes: 10
```

`clientSecret` рекомендуется передавать через Kubernetes Secret или переменную
окружения `GANGWAY_CLIENT_SECRET`. YAML-загрузчик не выполняет подстановку
`${GANGWAY_CLIENT_SECRET}` внутри файла конфигурации, поэтому эту строку нельзя
использовать как шаблон значения. Поле старого cookie-session ключа в актуальной
server-side реализации не требуется.

Приложение запускается с аргументом `-config /path/to/gangway.yaml`.
Переменные окружения имеют приоритет над YAML. Внешний адрес Gangway должен
использовать HTTPS: session cookie устанавливается с `Secure`, `HttpOnly`
и `SameSite=Lax`. TLS можно завершать на reverse proxy.

### Kubernetes API server

Kubernetes API server должен быть настроен для OIDC. Минимальный набор параметров:

```text
--oidc-issuer-url=https://issuer.example
--oidc-client-id=kubernetes-oidc
--oidc-username-claim=email
--oidc-groups-claim=groups
```

Подробнее см. официальную документацию Kubernetes:

<https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens>

## Сборка и тесты

Требуется Go 1.23 или совместимый Docker-образ Go 1.24.

Локальная проверка через Docker:

```powershell
docker run --rm -v "${PWD}:/src" -w /src golang:1.24-bookworm go test ./...
docker run --rm -v "${PWD}:/src" -w /src golang:1.24-bookworm go mod verify
```

Сборка контейнера:

```powershell
docker build -t gangway:local .
```

Образ — минимальный distroless static image, запускаемый от непривилегированного
пользователя.

## Kubernetes deployment

В репозитории сохранены оригинальные deployment-ресурсы и отдельные тестовые
ресурсы с суффиксом `-test`:

- `kubernetes/gangway-test-config.yaml`;
- `kubernetes/gangway-test-deployment.yaml`;
- `kubernetes/gangway-test-service.yaml`;
- `kubernetes/gangway-test-route.yaml`;
- `kubernetes/gangway-test.md`.

Тестовый deployment использует:

- namespace `dex`;
- одну replica;
- server-side in-memory sessions;
- non-root пользователя UID/GID `65532`;
- `RuntimeDefault` seccomp profile;
- read-only root filesystem;
- отключённый privilege escalation;
- сброшенные Linux capabilities;
- resource requests/limits;
- startup, readiness и liveness probes.

Актуальная инструкция тестового развёртывания находится в
[`kubernetes/gangway-test.md`](kubernetes/gangway-test.md).

Для нескольких replicas потребуется вынести session store в общее хранилище,
например Redis. In-memory store между pod не синхронизируется.

## Upstream и лицензия

Исходный проект:

- репозиторий: <https://github.com/heptiolabs/gangway>;
- исходная документация: [`docs/README.md`](docs/README.md);
- лицензия: Apache License 2.0.

Локальные изменения этого репозитория развиваются отдельно и не должны
предполагать полной совместимости с историческими deployment-инструкциями
upstream без проверки конфигурации.
