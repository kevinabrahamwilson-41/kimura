#!/usr/bin/env python3
import asyncio
import time
import statistics
from pathlib import Path
from kimura.protocol.state_machine import StateMachine
from kimura.protocol.constants import DEFAULT_PORT

import logging
PROJECT_ROOT = Path(__file__).parent.parent.absolute()
import sys
sys.path.insert(0, str(PROJECT_ROOT))


logging.basicConfig(
    level=logging.INFO, 
    format="%(asctime)s %(levelname)-5s %(message)s"
)
log = logging.getLogger("pqc_handshake")


async def client_handshake(key_path: str):
    start = time.perf_counter()
    reader, writer = await asyncio.open_connection("127.0.0.1", DEFAULT_PORT)
    sm = StateMachine(key_path, "client")

    # 1. Full handshake
    await sm.transition("send_handshake", reader=reader, writer=writer)

    # 2. Server echoes back handshake OK (your existing ack)
    # 3. Client/Server close
    writer.close()
    await writer.wait_closed()

    duration_ms = (time.perf_counter() - start) * 1000
    return duration_ms


async def server_handshake(key_path: str):
    async def handle_one(reader, writer):
        sm = StateMachine(key_path, "server")
        try:
            await sm.transition("recv_handshake", reader=reader, writer=writer)
            await sm.transition("send_response", reader=reader, writer=writer)
        except Exception as e:
            log.error(f"server handshake error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handle_one, "127.0.0.1", DEFAULT_PORT)
    log.info("PQC HANDSHAKE server listening...")
    async with server:
        await asyncio.Future()


async def main():
    key_path = "./keys"
    iterations = 10000

    # Start server in background
    server_task = asyncio.create_task(server_handshake(key_path))
    await asyncio.sleep(0.1)  # Let server bind

    latencies_ms = []
    for i in range(iterations):
        t = await client_handshake(key_path)
        latencies_ms.append(t)
        if (i + 1) % 100 == 0:
            log.info(f"handshake {i+1}/{iterations}: {t:.2f} ms")

    server_task.cancel()

    # Metrics
    print("\n" + "=" * 60)
    print("PQC HANDSHAKE LATENCY BENCHMARK (ML-KEM-768)")
    print("=" * 60)
    print(f"Requests   : {len(latencies_ms)}")
    print(f"Min        : {min(latencies_ms):.2f} ms")
    print(f"Median     : {statistics.median(latencies_ms):.2f} ms")
    print(f"90th       : {statistics.quantiles(latencies_ms, n=10)[8]:.2f} ms")
    print(f"99th       : {statistics.quantiles(latencies_ms, n=100)[98]:.2f} ms")
    print(f"Worst      : {max(latencies_ms):.2f} ms")
    print(f"Mean       : {statistics.mean(latencies_ms):.2f} ms")


if __name__ == "__main__":
    asyncio.run(main())
