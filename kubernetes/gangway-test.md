# Тестовый Gangway с server-side sessions

Тестовая установка использует:

- Deployment: `gangway-test`;
- Service: `gangway-test`;
- HTTPRoute: `gangway-test`;
- ConfigMap: `gangway-test`;
- существующий Secret: `gangway-secrets`;
- периодическая очистка истёкших in-memory сессий;
- URL: `https://gangway.gistech.mng`;
- OIDC client ID: тот же, что у текущей установки.

Перед применением нужно добавить в Dex callback URL:

```text
https://gangway.gistech.mng/callback
```

Сборка и публикация образа:

```powershell
docker build -t nexus-infra.admins-infra.common.pd34.udp.gtn/gangway/gangway:test-inmemory-v13 .
docker push nexus-infra.admins-infra.common.pd34.udp.gtn/gangway/gangway:test-inmemory-v13
```

Тестовый Deployment закреплён на digest образа
`sha256:634c961950073e07c34a12dfa5d869ff94b11f52c1d2ce93cf24d5dd471bb773`.

Применение:

```powershell
$env:KUBECONFIG = 'C:\Users\fenix\AppData\Roaming\Freelens\kubeconfigs\a68e4e8f-1328-4c07-b398-cf0d482a5b03'
kubectl apply -f .\kubernetes\gangway-test-config.yaml
kubectl apply -f .\kubernetes\gangway-test-deployment.yaml
kubectl apply -f .\kubernetes\gangway-test-service.yaml
kubectl apply -f .\kubernetes\gangway-test-route.yaml
kubectl rollout status deployment/gangway-test -n dex
```

Сессии хранятся в памяти pod. После рестарта тестового pod пользователям потребуется повторная авторизация. Рабочий Deployment не изменяется.
