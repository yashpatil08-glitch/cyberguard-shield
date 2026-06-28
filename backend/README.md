# CyberGuard API

FastAPI wrapper around the CyberGuard Python security modules. The
business logic in `backend/services/` and `backend/utils/` is **not**
modified — the FastAPI layer in `backend/app/` only wires those modules
to HTTP endpoints.

## Endpoints

| Method | Path                      | Module                                  |
| ------ | ------------------------- | --------------------------------------- |
| GET    | `/api/health`             | health check                            |
| POST   | `/api/url-check`          | `services.url_analyzer.URLAnalyzer`     |
| POST   | `/api/password-strength`  | `services.password_strength`            |
| POST   | `/api/security-headers`   | `services.security_headers`             |
| POST   | `/api/phishing-detect`    | `services.phishing_detector`            |
| POST   | `/api/report`             | `services.pdf_generator` (returns PDF)  |

Interactive docs: `/docs` (Swagger) and `/redoc`.

## Local development

Run from the **repo root** (the internal modules use absolute
`from backend...` imports):

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r backend/requirements.txt
uvicorn backend.app.main:app --reload
```

Server runs on http://127.0.0.1:8000.

## Deploy to Render

1. Push this repo to GitHub.
2. In Render: **New → Blueprint** → pick the repo. `render.yaml` is
   auto-detected (root directory: `backend/`).
3. After the first deploy, set `CORS_ORIGINS` to your frontend origin,
   e.g. `https://your-app.lovable.app`. Wildcard works for testing.
4. Copy the public URL (e.g. `https://cyberguard-api.onrender.com`) and
   paste it into the frontend **Settings → Backend API**.

The start command is:

```
uvicorn backend.app.main:app --host 0.0.0.0 --port $PORT
```

## Environment variables

| Name           | Default       | Purpose                              |
| -------------- | ------------- | ------------------------------------ |
| `PORT`         | provided      | Bound by Render                      |
| `ENVIRONMENT`  | `production`  | Reported in `/api/health`            |
| `LOG_LEVEL`    | `INFO`        | Root logger level                    |
| `CORS_ORIGINS` | `*`           | Comma-separated allowed origins      |
| `REQUEST_TIMEOUT` | `10`       | Default outbound HTTP timeout (s)    |