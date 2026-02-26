from os import getenv

from fastapi import FastAPI

app = FastAPI(
    title="KA Facility OS",
    description="Starter API for apartment facility operations",
    version="0.1.0",
)


@app.get("/")
def root() -> dict[str, str]:
    return {
        "service": "ka-facility-os",
        "status": "running",
        "docs": "/docs",
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/meta")
def meta() -> dict[str, str]:
    return {"env": getenv("ENV", "local")}
