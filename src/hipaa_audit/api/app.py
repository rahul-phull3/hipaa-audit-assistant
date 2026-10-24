"""The Starlette application: routes, error mapping, middleware and the optional static UI."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import anyio
from python_multipart.exceptions import MultipartParseError
from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from hipaa_audit import __version__
from hipaa_audit.api.middleware import (
    ApiKeyMiddleware,
    BodyLimitMiddleware,
    BodyTooLarge,
    ErrorBoundaryMiddleware,
    SecurityHeadersMiddleware,
    error_body,
)
from hipaa_audit.config import Settings
from hipaa_audit.service import (
    AuditService,
    Busy,
    Conflict,
    InvalidRequest,
    NotFound,
    ServiceError,
    TooLarge,
    Unavailable,
)

MULTIPART_OVERHEAD = 64 * 1024  # form fields and boundaries around the file
STATUS_FOR_ERROR: dict[type[ServiceError], tuple[int, str]] = {
    NotFound: (404, "not_found"),
    InvalidRequest: (422, "invalid_request"),
    TooLarge: (413, "too_large"),
    Conflict: (409, "conflict"),
    Busy: (429, "busy"),
    Unavailable: (503, "unavailable"),
}


def _json_error(status: int, code: str, message: str, headers: dict[str, str] | None = None) -> Response:
    return Response(error_body(code, message), status_code=status, media_type="application/json", headers=headers)


def _audit_payload(service: AuditService, audit_id: str) -> dict[str, Any]:
    record = service.get(audit_id)
    return {**record.model_dump(mode="json"), "summary": service.summary(audit_id)}


def _service(request: Request) -> AuditService:
    return request.app.state.service


async def _in_thread(function, *args):
    return await anyio.to_thread.run_sync(function, *args)


# -- handlers ------------------------------------------------------------------------------------------------------------


async def health(request: Request) -> Response:
    return JSONResponse({"status": "ok", "version": __version__})


async def status(request: Request) -> Response:
    return JSONResponse(await _in_thread(_service(request).health))


async def controls(request: Request) -> Response:
    return JSONResponse(_service(request).control_catalog())


def _split_controls(values: list[Any]) -> list[str] | None:
    ids = [part.strip() for value in values if isinstance(value, str) for part in value.split(",") if part.strip()]
    return ids or None


async def _read_form(request: Request):
    """Parse the multipart body. A malformed or oversized form is the client's mistake, not a server error."""
    try:
        return await request.form(max_files=1, max_fields=5)
    except HTTPException as exc:  # Starlette reports a missing boundary, too many parts and similar as 400
        raise InvalidRequest(f"The upload could not be read ({exc.detail}).") from None
    except MultipartParseError:
        raise InvalidRequest("The upload is not valid multipart/form-data.") from None


async def create_audit(request: Request) -> Response:
    service = _service(request)
    max_bytes = service.settings.max_upload_bytes
    form = await _read_form(request)
    try:
        upload = form.get("file")
        if upload is None or isinstance(upload, str):
            raise InvalidRequest("Attach the policy document as a form field named 'file'.")
        data = await upload.read(max_bytes + 1)
        selected = _split_controls(form.getlist("controls"))
        record = await _in_thread(service.submit, upload.filename, data, selected)
    finally:
        await form.close()
    service.start(record.id)
    return JSONResponse(
        _audit_payload(service, record.id), status_code=202, headers={"Location": f"/api/audits/{record.id}"}
    )


async def list_audits(request: Request) -> Response:
    try:
        limit = int(request.query_params.get("limit", "50"))
        offset = int(request.query_params.get("offset", "0"))
    except ValueError:
        raise InvalidRequest("limit and offset must be whole numbers.") from None
    service = _service(request)
    return JSONResponse({"audits": service.list_summaries(limit, offset), "total": service.repo.count_audits()})


async def get_audit(request: Request) -> Response:
    service = _service(request)
    return JSONResponse(_audit_payload(service, request.path_params["audit_id"]))


async def get_findings(request: Request) -> Response:
    return JSONResponse({"findings": _service(request).finding_views(request.path_params["audit_id"])})


async def get_chunk(request: Request) -> Response:
    p = request.path_params
    return JSONResponse(_service(request).chunk_context(p["audit_id"], p["chunk_id"]))


async def get_report(request: Request) -> Response:
    fmt = request.query_params.get("format", "md")
    content, media_type, filename = _service(request).report(request.path_params["audit_id"], fmt)
    return Response(content, media_type=media_type, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


async def cancel_audit(request: Request) -> Response:
    service = _service(request)
    service.cancel(request.path_params["audit_id"])
    return JSONResponse(_audit_payload(service, request.path_params["audit_id"]))


async def rerun_audit(request: Request) -> Response:
    service = _service(request)
    record = await _in_thread(service.rerun, request.path_params["audit_id"])
    service.start(record.id)
    return JSONResponse(
        _audit_payload(service, record.id), status_code=202, headers={"Location": f"/api/audits/{record.id}"}
    )


async def delete_audit(request: Request) -> Response:
    _service(request).delete(request.path_params["audit_id"])
    return Response(status_code=204)


# -- errors ------------------------------------------------------------------------------------------------------------------


async def service_error(request: Request, exc: Exception) -> Response:
    assert isinstance(exc, ServiceError)
    status_code, code = next((v for k, v in STATUS_FOR_ERROR.items() if isinstance(exc, k)), (400, "bad_request"))
    headers = {"Retry-After": "30"} if isinstance(exc, Busy) else None
    return _json_error(status_code, code, exc.message, headers)


async def body_too_large(request: Request, exc: Exception) -> Response:
    return _json_error(413, "too_large", "The upload is larger than the allowed size.")


async def http_error(request: Request, exc: Exception) -> Response:
    assert isinstance(exc, HTTPException)
    code = {404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "error")
    message = "No such resource." if exc.status_code == 404 else exc.detail
    return _json_error(exc.status_code, code, message, dict(exc.headers or {}))


# -- assembly ------------------------------------------------------------------------------------------------------------------


def _static_dir(settings: Settings) -> Path | None:
    candidates = [Path(settings.static_dir)] if settings.static_dir else [Path(__file__).resolve().parents[3] / "ui" / "dist"]
    return next((p for p in candidates if (p / "index.html").is_file()), None)


def create_app(settings: Settings | None = None, service: AuditService | None = None) -> Starlette:
    settings = settings or Settings.from_env()
    service = service or AuditService.from_settings(settings)

    @asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        yield
        await service.shutdown()

    api = [
        Route("/api/health", health, methods=["GET"]),
        Route("/api/status", status, methods=["GET"]),
        Route("/api/controls", controls, methods=["GET"]),
        Route("/api/audits", create_audit, methods=["POST"]),
        Route("/api/audits", list_audits, methods=["GET"]),
        Route("/api/audits/{audit_id}", get_audit, methods=["GET"]),
        Route("/api/audits/{audit_id}", delete_audit, methods=["DELETE"]),
        Route("/api/audits/{audit_id}/findings", get_findings, methods=["GET"]),
        Route("/api/audits/{audit_id}/chunks/{chunk_id}", get_chunk, methods=["GET"]),
        Route("/api/audits/{audit_id}/report", get_report, methods=["GET"]),
        Route("/api/audits/{audit_id}/cancel", cancel_audit, methods=["POST"]),
        Route("/api/audits/{audit_id}/rerun", rerun_audit, methods=["POST"]),
    ]
    static = _static_dir(settings)
    if static is not None:
        routes = [*api, Mount("/", app=StaticFiles(directory=static, html=True), name="ui")]
    else:

        async def root(request: Request) -> Response:
            return JSONResponse({"name": "hipaa-audit-assistant", "version": __version__, "api": "/api/health", "ui": "not built"})

        routes = [*api, Route("/", root, methods=["GET"])]

    # Outermost first: security headers wrap everything, then CORS, then the error boundary, the API key and the body limit.
    middleware = [Middleware(SecurityHeadersMiddleware)]
    if settings.cors_origins:
        middleware.append(
            Middleware(
                CORSMiddleware,
                allow_origins=list(settings.cors_origins),
                allow_methods=["GET", "POST", "DELETE"],
                allow_headers=["X-API-Key", "Content-Type"],
                expose_headers=["Content-Disposition", "Location"],
            )
        )
    middleware += [
        Middleware(ErrorBoundaryMiddleware),
        Middleware(ApiKeyMiddleware, api_key=settings.api_key),
        Middleware(BodyLimitMiddleware, max_bytes=settings.max_upload_bytes + MULTIPART_OVERHEAD),
    ]
    handlers: dict[Any, Any] = {
        ServiceError: service_error,
        BodyTooLarge: body_too_large,
        HTTPException: http_error,
    }
    app = Starlette(routes=routes, middleware=middleware, exception_handlers=handlers, lifespan=lifespan)
    app.state.service = service
    return app
