# ka-facility-os

`ka-facility-os` is an isolated FastAPI starter project for your apartment facility operations service.

## 1) Local run (Windows / PowerShell)

```powershell
cd C:\ka-facility-os
.\.venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8001
```

Open:
- API: `http://127.0.0.1:8001`
- Docs: `http://127.0.0.1:8001/docs`
- Health: `http://127.0.0.1:8001/health`

## 2) Git init and first commit

```powershell
git init
git branch -M main
git add .
git commit -m "chore: bootstrap ka-facility-os"
```

## 3) GitHub push

```powershell
git remote add origin https://github.com/<your-id>/<your-repo>.git
git push -u origin main
```

## 4) Render deploy

Use this repo in Render as a Web Service.

- Build command: `pip install -r requirements.txt`
- Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
- Health check path: `/health`

`render.yaml` is already included for infrastructure-as-code style deployment.
