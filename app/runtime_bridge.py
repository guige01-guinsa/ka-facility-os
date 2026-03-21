"""Helpers for reading already-loaded app.main symbols without direct imports."""

from __future__ import annotations

import sys
from typing import Any, Iterable


def require_main_module() -> Any:
    main_module = sys.modules.get("app.main")
    if main_module is None:
        raise RuntimeError("app.main must be imported before using this bridge.")
    return main_module


def export_main_symbols(namespace: dict[str, Any], names: Iterable[str]) -> None:
    main_module = require_main_module()
    missing: list[str] = []
    for name in names:
        if hasattr(main_module, name):
            namespace[name] = getattr(main_module, name)
        else:
            missing.append(name)
    if missing:
        joined = ", ".join(sorted(missing))
        raise AttributeError(f"app.main is missing required bridge symbols: {joined}")


def export_main_symbols_with_prefixes(
    namespace: dict[str, Any],
    *,
    names: Iterable[str] = (),
    prefixes: Iterable[str] = (),
) -> None:
    export_main_symbols(namespace, names)
    main_module = require_main_module()
    prefix_list = tuple(prefixes)
    if not prefix_list:
        return
    for name, value in vars(main_module).items():
        if any(name.startswith(prefix) for prefix in prefix_list):
            namespace[name] = value


class MainRuntimeProxy:
    def __getattr__(self, name: str) -> Any:
        main_module = require_main_module()
        if not hasattr(main_module, name):
            raise AttributeError(name)
        return getattr(main_module, name)


main_runtime = MainRuntimeProxy()
