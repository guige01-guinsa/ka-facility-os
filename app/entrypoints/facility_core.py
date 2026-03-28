"""Facility-core ASGI entrypoint."""

from os import getenv

from app.entrypoints.split_apps import create_facility_core_app


def _env_bool(name: str, default: bool = False) -> bool:
    raw = getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


app = create_facility_core_app(
    run_background_automation=_env_bool("SPLIT_APP_RUN_BACKGROUND_AUTOMATION", False)
)
