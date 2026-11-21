# Тестовый Gangway в текущем кластере

Эти manifests отдельны от `dex-k8s-authenticator`:

- текущий генератор: `https://k8s-login.gistech.mng`;
- тестовый Gangway: `https://login-k8s.gistech.mng`;
- общий OIDC issuer: `https://dex.gistech.mng`;
- разные Dex static clients и callback URI;
- разные Deployment, Service и HTTPRoute.

Перед применением:

1. Соберите образ из `F:\gangway`.
2. Опубликуйте его в Nexus с tag `0.1.0-hardened`.
3. Создайте `gangway-secrets` из `gangway-secret.example.yaml`, заменив все
   placeholders реальными значениями.
4. Укажите в Secret два разных CA:

   - `ca.crt` — CA для TLS Dex;
   - `cluster-ca.crt` — CA сертификата Kubernetes API server.

5. Добавьте в Dex отдельный static client:

```yaml
- id: login-k8s.gistech.mng
  name: login-k8s.gistech.mng
  secret: <GANGWAY_OIDC_CLIENT_SECRET>
  redirectURIs:
    - https://login-k8s.gistech.mng/callback
```

6. После `helm upgrade` Dex должен содержать новый redirect URI.

Production управляется Helm chart из `../charts/gangway`. Файлы
`gangway-config.yaml`, `gangway-deployment.yaml`, `gangway-service.yaml` и
`gangway-route.yaml` сохранены как reference; не применяйте их поверх Helm-managed
production ресурсов.

Для тестового окружения применение ресурсов:

```powershell
kubectl apply -f .\gangway-secret.yaml
kubectl apply -f .\gangway-config.yaml
kubectl apply -f .\gangway-deployment.yaml
kubectl apply -f .\gangway-service.yaml
kubectl apply -f .\gangway-route.yaml
```

Проверка:

```powershell
kubectl get pods,svc,httproute -n dex
kubectl rollout status deployment/gangway -n dex
```

Ожидаемые проверки:

```text
https://login-k8s.gistech.mng/healthz -> 200
https://login-k8s.gistech.mng/ -> login page
https://login-k8s.gistech.mng/login -> redirect to Dex
```
