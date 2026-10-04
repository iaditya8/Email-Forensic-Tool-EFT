# Split Deployment (Backend + Vercel Frontend)

This repository supports a split architecture:

- **Backend**: FastAPI service (Render/Railway/Fly.io/VPS/Docker)
- **Frontend**: static dashboard on Vercel from `/frontend`

## 1) Backend deployment

### ASGI entrypoint

- Entrypoint module: `api/index.py`
- Exported app object: `app`

Start command:

```bash
uvicorn api.index:app --host 0.0.0.0 --port ${PORT:-8000}
```

Health check URL:

```text
https://your-backend.example.com/health
```

### Environment variables

- `PORT` (provided by most hosts)
- `EFT_CORS_ALLOW_ORIGINS` (comma-separated origins), example:
  - `https://your-frontend.vercel.app`

Do **not** use wildcard origins when deploying with a separate frontend origin.

### Docker deployment

Build and run:

```bash
docker build -t eft-backend .
docker run --rm -p 8000:8000 \
  -e PORT=8000 \
  -e EFT_CORS_ALLOW_ORIGINS="https://your-frontend.vercel.app" \
  eft-backend
```

## 2) Frontend deployment on Vercel

Frontend source is in `/frontend` and is built with Vite.

### Vercel project settings

- **Root Directory**: `frontend`
- **Build Command**: `npm run build`
- **Output Directory**: `dist`

### Required frontend environment variable

- `VITE_API_BASE_URL=https://your-backend.example.com`

The dashboard builds API requests as `${VITE_API_BASE_URL}/api/...` and safely normalizes trailing slashes.

## 3) Local development (split mode)

Backend:

```bash
poetry run uvicorn api.index:app --host 127.0.0.1 --port 8000
```

Frontend:

```bash
cd frontend
npm install
VITE_API_BASE_URL=http://127.0.0.1:8000 npm run dev
```

## 4) Known deployment limitations

- Heavy forensic workloads (large uploads, PCAP/EVTX/memory scans, report generation) are compute and memory intensive.
- Prefer a long-running backend service (container/VPS) for these workloads instead of serverless execution limits.
