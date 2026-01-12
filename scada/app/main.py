import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from starlette.middleware.cors import CORSMiddleware
from config import HOST, PORT, APP_NAME, CONCURRENCY_LIMIT
from routers import auth, devices, diagnostics, logs, monitoring 
from middleware.session_middleware import SessionMonitorMiddleware


def get_application(lifespan=None):
    """
    Function to create and configure the FastAPI application instance.
    This function adds middleware for CORS and returns the configured application instance.
    """
    _app = FastAPI(
        title=APP_NAME,
        debug=False,
        lifespan=lifespan
    )
    _app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    _app.add_middleware(SessionMonitorMiddleware)
    return _app


app = get_application()
app.include_router(auth.router, prefix="/auth")
app.include_router(devices.router, prefix="/api/devices")
app.include_router(diagnostics.router, prefix="/api/diagnostics")
app.include_router(logs.router, prefix="/api/logs")
app.include_router(monitoring.router, prefix="/api/monitoring")


@app.get("/", response_class=HTMLResponse)
async def root():
    """
    GET endpoint to redirect the users to My API UI.
    Returns an HTMLResponse containing the Redirecting UI.
    """
    with open("static/root.html", "r", encoding="utf-8") as f:
        html_content = f.read()

    return HTMLResponse(content=html_content, status_code=200)


@app.get("/monitoring", response_class=HTMLResponse)
async def monitoring_root():
    """
    GET endpoint to redirect the users to Monitoring System UI.
    Returns an HTMLResponse containing the Redirecting UI.
    """
    with open("static/monitoring.html", "r", encoding="utf-8") as f:
        html_content = f.read()

    return HTMLResponse(content=html_content, status_code=200)


if __name__ == '__main__':
    uvicorn.run(
        app,
        host=HOST,
        port=int(PORT),
        log_level="info",
        limit_concurrency=CONCURRENCY_LIMIT
    )