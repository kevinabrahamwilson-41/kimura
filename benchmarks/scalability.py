#!/usr/bin/env python3
import asyncio
import time
import functools
from typing import List
from kimura.session.manager import SessionManager


class Scalability:
    """
    Scalability benchmark for PQC handshake‑heavy concurrent channel establishment.

    Clients: 1 → 10 → 50 → 100
    Measures:
      - total wall‑time to complete all handshakes
      - avg per‑client handshake time
      - concurrency pressure on the server.
    """

    BENCHMARKS = [
        {"name": "1 client",      "n": 1},
        {"name": "5 clients",     "n": 5},
        {"name": "10 clients",    "n": 10},
        {"name": "50 clients",    "n": 50},
        {"name": "100 clients",   "n": 100},
    ]

    def __init__(self, key_path: str = "keys/", host: str = "127.0.0.1", port: int = 8443):
        self.key_path = key_path
        self.host = host
        self.port = port


    async def run_n_clients(self, n: int) -> List[float]:
        """Run `n` concurrent clients and return their individual handshake durations."""
        start_global = time.perf_counter()
        tasks = []
        start_times = []
        end_times = []

        for _ in range(n):
            start = time.perf_counter()
            start_times.append(start)
            client = SessionManager("client", self.key_path)
            tasks.append(
                self._client_with_timing(client, start_times[-1], end_times)
            )

        await asyncio.gather(*tasks, return_exceptions=False)
        end_global = time.perf_counter()

        # Store per‑client duration
        durations = []
        for i in range(n):
            durations.append(end_times[i] - start_times[i])

        return durations, end_global - start_global


    async def _client_with_timing(
        self,
        client: SessionManager,
        start_time: float,
        end_times: List[float]
    ):
        """
        Wrap .establish_channel with duration tracking.
        """
        await client.establish_channel(host=self.host, port=self.port)
        end_times.append(time.perf_counter())


    async def run(self):
        """Run the full scalability matrix."""
        print("SCALABILITY BENCHMARK (PQC‑ENCRYPTED CHANNELS)")
        print("=" * 70)

        for b in self.BENCHMARKS:
            n = b["n"]
            print(f"\nClients: {n}")
            print("-" * 40)

            durations, total_time = await self.run_n_clients(n)

            print(f"Concurrency  : {n} parallel clients")
            print(f"Total time   : {total_time:.2f} s")

            durations_ms = [d * 1000 for d in durations]
            print(f"Avg per client : {sum(durations_ms)/n:.2f} ms")
            print(f"Min per client : {min(durations_ms):.2f} ms")
            print(f"90th percentile: sorted(durations_ms, n=10)[8] --> {sorted(durations_ms)[int(0.9*n)-1]:.2f} ms")  # 90th
            print(f"99th percentile: sorted(durations_ms, n=100)[98] --> {sorted(durations_ms)[int(0.99*n)-1]:.2f} ms")  # 99th
            print(f"Worst per client: {max(durations_ms):.2f} ms")


def main():
    # Set up extreme‑mode scaling
    scale = Scalability(
        key_path="keys/",
        host="127.0.0.1",
        port=8443,
    )
    asyncio.run(scale.run())


if __name__ == "__main__":
    main()
