# Deployment

## Docker Deployment

```bash
# Build the image
docker build -t nexus-strike .

# Run with local LLM (Ollama)
docker run -d \
  --name nexus-strike \
  -e LLM_PROVIDER=ollama \
  -e OLLAMA_BASE_URL=http://host.docker.internal:11434/v1 \
  -v ./engagements:/app/engagements \
  -v ./reports:/app/reports \
  nexus-strike

# Run assessment
docker exec nexus-strike nexus live --target 127.0.0.1
```

## Docker Compose

```bash
docker-compose up -d
```

This starts Nexus-Strike alongside Postgres and Redis for production deployments.

## Kubernetes (K8s)

Deploy using the manifests in `deploy/kubernetes/`:

```bash
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/configmap.yaml
kubectl apply -f deploy/kubernetes/deployment.yaml
kubectl apply -f deploy/kubernetes/service.yaml
```

## Terraform

Infrastructure-as-code deployments available in `deploy/terraform/`:

```bash
cd deploy/terraform
terraform init
terraform plan
terraform apply
```

## Production Checklist

1. Set strong API keys in environment variables
2. Configure `NEXUS_ALLOWED_TARGETS` with approved scopes only
3. Set `NEXUS_LEGAL_ACK=I_HAVE_WRITTEN_AUTHORIZATION`
4. Enable `NEXUS_SANDBOX_ENABLED=true` for destructive tools
5. Configure audit logging via `NEXUS_AUDIT_LOG` path
6. Set rate limits via `NEXUS_RATE_LIMIT_CALLS` and `NEXUS_RATE_LIMIT_WINDOW`
7. Use Postgres for mission persistence and Redis for rate limiting state
8. Run `nexus preflight --strict` to verify readiness

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_PROVIDER` | ollama | LLM backend (openai, anthropic, ollama, etc.) |
| `NEXUS_ALLOWED_TARGETS` | localhost,127.0.0.1 | Comma-separated scope allow-list |
| `NEXUS_LEGAL_ACK` | (empty) | Set to `I_HAVE_WRITTEN_AUTHORIZATION` to enable |
| `NEXUS_SANDBOX_ENABLED` | true | Sandbox dangerous tools |
| `NEXUS_LOG_LEVEL` | INFO | Logging verbosity |
| `NEXUS_RATE_LIMIT_CALLS` | 100 | Max calls per rate window |
| `NEXUS_RATE_LIMIT_WINDOW` | 60 | Rate window in seconds |