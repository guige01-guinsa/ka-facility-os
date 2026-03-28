"""Platform-admin ASGI entrypoint."""

from os import getenv

from app.entrypoints.split_apps import create_platform_admin_app


def _run_database_migrations_by_default() -> bool:
    env_name = getenv("ENV", "local").strip().lower()
    return env_name in {"local", "test"}


app = create_platform_admin_app(
    run_background_automation=False,
    run_database_migrations=_run_database_migrations_by_default(),
)
