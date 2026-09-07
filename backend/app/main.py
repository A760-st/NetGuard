from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.core.logging import get_logger
from app.database.connection import init_db, close_db
from app.api import health, pcap_jobs, flows, alerts, incidents, hosts, analytics

logger = get_logger("main")
settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("starting_netguard", environment=settings.environment)
    try:
        await init_db()
        logger.info("database_initialized")
    except Exception as e:
        logger.error("database_init_failed", error=str(e))
    yield
    logger.info("shutting_down_netguard")
    await close_db()


app = FastAPI(
    title="NETGUARD",
    description="AI-Based Detection of Cyber Threats in Unidirectional IP Traffic",
    version=settings.app_version,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(pcap_jobs.router)
app.include_router(flows.router)
app.include_router(alerts.router)
app.include_router(incidents.router)
app.include_router(hosts.router)
app.include_router(analytics.router)
