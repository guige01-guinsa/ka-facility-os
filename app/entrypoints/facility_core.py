"""Facility-core ASGI entrypoint."""

from app.entrypoints.split_apps import create_facility_core_app


app = create_facility_core_app(run_background_automation=False)
