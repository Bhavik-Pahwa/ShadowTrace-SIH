from fastapi import HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


class ShadowTraceError(Exception):
    def __init__(self, code: int, message: str, details: str):
        self.code = code
        self.message = message
        self.details = details
        super().__init__(message)


def error_payload(code: int, message: str, details: str) -> dict:
    return {
        "status": "error",
        "code": code,
        "message": message,
        "details": details,
    }


def raise_error(code: int, message: str, details: str) -> None:
    raise ShadowTraceError(code, message, details)


async def shadowtrace_exception_handler(_, exc: ShadowTraceError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.code,
        content=error_payload(exc.code, exc.message, exc.details),
    )


async def http_exception_handler(_, exc: HTTPException) -> JSONResponse:
    detail = exc.detail if isinstance(exc.detail, str) else "HTTP request failed."
    return JSONResponse(
        status_code=exc.status_code,
        content=error_payload(exc.status_code, detail, detail),
    )


async def validation_exception_handler(_, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content=error_payload(422, "Malformed request.", str(exc.errors())),
    )


async def unhandled_exception_handler(_, exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=500,
        content=error_payload(500, "Internal server error.", str(exc)),
    )
