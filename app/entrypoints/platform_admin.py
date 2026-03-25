"""Platform-admin ASGI entrypoint."""

from app.entrypoints.split_apps import create_platform_admin_app


app = create_platform_admin_app(run_background_automation=False)
