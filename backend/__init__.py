"""DocVault plugin registration."""


def _ensure_schema_compat(get_db):
    from .schema import ensure_docvault_schema

    db_generator = get_db()
    db = next(db_generator)
    try:
        ensure_docvault_schema(db)
    finally:
        db_generator.close()


def register_plugin(app, mcp_registry=None, feature_gate=None):
    from .router import get_db, router

    @app.on_event("startup")
    def ensure_docvault_plugin_schema() -> None:
        _ensure_schema_compat(get_db)

    try:
        _ensure_schema_compat(get_db)
    except Exception:
        pass

    app.include_router(router, prefix="/api/v1/docvault", tags=["docvault"])
    return {
        "name": "docvault",
        "version": "1.0.0",
        "routes": ["/api/v1/docvault"],
    }
