from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.models.database import init_db
from app.routers import auth, scans, reports

app = FastAPI(
    title=settings.APP_NAME,
    description=(
        "Automated Security Assessment and Vulnerability Analysis Platform. "
        "For use only against applications where written testing authorization "
        "has been obtained. See docs/scope_and_authorization.md."
    ),
    version="1.0.0",
)

# Allow the React dev server to call the API. Tighten this for production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(scans.router)
app.include_router(reports.router)


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/health", tags=["System"])
def health_check():
    return {"status": "ok", "app": settings.APP_NAME}
