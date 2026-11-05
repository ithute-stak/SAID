"""Real in-process ASGI concurrency exercise against synthetic, ephemeral CI only.

No public URL, subscriber input, carrier I/O, writes or production deployment.
"""
import asyncio
import json
import os
import statistics
import time
from collections import Counter

import httpx
from said.main import app

assert os.environ.get("SAID_CONCURRENCY_TEST_DB") == "ephemeral-ci-only"
assert os.environ.get("SAID_ENVIRONMENT") == "test"

REQUESTS = 160
CONCURRENCY = 16


async def exercise():
    sem = asyncio.Semaphore(CONCURRENCY)
    timings = []
    codes = Counter()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://said-ci.invalid",
                                 timeout=10) as client:
        async def one(index):
            async with sem:
                start = time.perf_counter()
                if index % 2:
                    response = await client.get("/health")
                    assert response.status_code == 200, response.text
                    assert response.json() == {"status": "ok", "service": "said-api"}
                else:
                    response = await client.get(
                        "/api/v1/devices/00000000-0000-4000-8000-000000000000")
                    # This unauthenticated request must never expose a device.
                    assert response.status_code in (401, 403), response.text
                codes[response.status_code] += 1
                timings.append((time.perf_counter() - start) * 1000)

        await asyncio.gather(*(one(i) for i in range(REQUESTS)))

    ordered = sorted(timings)
    p95 = ordered[max(0, int(len(ordered) * 0.95 + 0.9999) - 1)]
    report = {
        "schema": "said.mock.ephemeral-asgi-load.v1",
        "transport": "in_process_asgi",
        "requests": REQUESTS,
        "concurrency": CONCURRENCY,
        "p95_ms": round(p95, 2),
        "max_ms": round(max(timings), 2),
        "health_successes": codes[200],
        "unauthorized_denials": codes[401] + codes[403],
        "real_network_latency_measured": False,
        "actual_staging_server_measured": False,
        "staging_deploy_authorized": False,
        "production_deploy_authorized": False,
    }
    print(json.dumps(report, sort_keys=True))
    assert len(timings) == REQUESTS
    assert codes[200] == REQUESTS // 2
    assert codes[401] + codes[403] == REQUESTS // 2
    # Wide, stable CI smoke ceiling; not a benchmark/SLA.
    assert p95 < 5000, "In-process synthetic endpoint p95 exceeded smoke ceiling"


if __name__ == "__main__":
    asyncio.run(exercise())
