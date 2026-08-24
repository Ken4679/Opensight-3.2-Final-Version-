"""Pytest configuration and environment setup for tests."""
# Starlette 1.x / FastAPI compatibility layer
try:
    import starlette.routing
    import starlette.applications

    _orig_router_init = starlette.routing.Router.__init__
    def _safe_router_init(self, *args, **kwargs):
        kwargs.pop("on_startup", None)
        kwargs.pop("on_shutdown", None)
        return _orig_router_init(self, *args, **kwargs)
    starlette.routing.Router.__init__ = _safe_router_init

    _orig_starlette_init = starlette.applications.Starlette.__init__
    def _safe_starlette_init(self, *args, **kwargs):
        kwargs.pop("on_startup", None)
        kwargs.pop("on_shutdown", None)
        return _orig_starlette_init(self, *args, **kwargs)
    starlette.applications.Starlette.__init__ = _safe_starlette_init
except Exception:
    pass
