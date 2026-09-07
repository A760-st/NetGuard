import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_health_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "version" in data
        assert data["version"] == "0.1.0"


@pytest.mark.anyio
async def test_system_status():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/system/status")
        assert response.status_code == 200
        data = response.json()
        assert "version" in data
        assert "database" in data
        assert "redis" in data


@pytest.mark.anyio
async def test_analytics_overview():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/analytics/overview")
        assert response.status_code == 200
        data = response.json()
        assert "total_flows" in data
        assert "total_alerts" in data
        assert "total_incidents" in data


@pytest.mark.anyio
async def test_list_jobs():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/pcap/jobs")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
        assert "page" in data


@pytest.mark.anyio
async def test_list_flows():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/flows")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data


@pytest.mark.anyio
async def test_list_alerts():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/alerts")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data


@pytest.mark.anyio
async def test_list_incidents():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/incidents")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data


@pytest.mark.anyio
async def test_analytics_threats():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/analytics/threats")
        assert response.status_code == 200
        data = response.json()
        assert "threats" in data


@pytest.mark.anyio
async def test_analytics_protocols():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/analytics/protocols")
        assert response.status_code == 200
        data = response.json()
        assert "protocols" in data


@pytest.mark.anyio
async def test_analytics_top_talkers():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/analytics/top-talkers")
        assert response.status_code == 200
        data = response.json()
        assert "top_talkers" in data
