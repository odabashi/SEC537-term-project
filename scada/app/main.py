import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from starlette.middleware.cors import CORSMiddleware
from config import HOST, PORT, CONCURRENCY_LIMIT


def get_application(lifespan=None):
    """
    Function to create and configure the FastAPI application instance.
    This function adds middleware for CORS and returns the configured application instance.
    """
    _app = FastAPI(
        title="My Project",
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
    return _app


app = get_application()
# app.include_router(project.router)


@app.get("/")
async def get():
    """
    GET endpoint to redirect the users to My API UI.
    Returns an HTMLResponse containing the Redirecting UI.
    """
    html = f"""
    <!DOCTYPE html>
    <html>
        <head>
            <title>My API</title>
                <!-- Bootstrap CSS -->
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet" 
            integrity="sha384-EVSTQN3/azprG1Anm3QDgpJLIm9Nao0Yz1ztcQTwFspd3yD65VohhpuuCOmLASjC" crossorigin="anonymous">
        </head>
        <body>
            <div style="display: flex; justify-content: center; align-items: center; flex-direction: column; position: 
            absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);">
                <h1 align="center">Welcome to My API!</h1>
                <a href="/docs/">
                    <button class="btn btn-outline-primary mt-2">Explore the API</button>
                </a>
            </div>
        </body>
    </html>
    """
    return HTMLResponse(html)


if __name__ == '__main__':
    uvicorn.run(
        app,
        host=HOST,
        port=int(PORT),
        log_level="info",
        limit_concurrency=CONCURRENCY_LIMIT
    )
