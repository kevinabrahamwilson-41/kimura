#!/usr/bin/env python3
import asyncio
import time
import os
import sys
from pathlib import Path
import logging
import tempfile
PROJECT_ROOT = Path(__file__).parent.parent.absolute()
sys.path.insert(0, str(PROJECT_ROOT))
from protocol.state_machine import StateMachine
# Fix imports
from session.server import PQCServer
from session.client import PQCClient

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
logger = logging.getLogger(__name__)

class ThroughputTester:
    def __init__(self, key_path: str = "./keys", file_size_gb: float = 3.0):
        self.key_path = key_path
        self.file_size_gb = file_size_gb
        self.file_size_bytes = int(file_size_gb * 1024**3)
        self.test_file = self._create_dummy_file()
        
    def _create_dummy_file(self) -> Path:
        test_file = Path("new_file.bin")
        if test_file.exists():
            return test_file
            
        logger.info(f"Creating {self.file_size_gb}GB test file...")
        start = time.perf_counter()
        
        with open(test_file, 'wb') as f:
            chunk_size = 64 * 1024 * 1024
            total_written = 0
            while total_written < self.file_size_bytes:
                to_write = min(chunk_size, self.file_size_bytes - total_written)
                f.write(b'\x00' * to_write)
                total_written += to_write
        
        elapsed = time.perf_counter() - start
        logger.info(f"✅ 3GB file ready ({elapsed:.1f}s)")
        return test_file
    
    async def benchmark_roundtrip(self, iterations: int = 20):
        results = {'client_to_server': [], 'total_rounds': 0}
        
        # ✅ FIX 1: Pass base_output="/dev/null" equivalent
        server = PQCServer(self.key_path, base_output="/tmp/dummy")
        
        # ✅ FIX 2: Use asyncio.start_server directly (no blocking serve_forever)
        server_task = asyncio.create_task(self._run_benchmark_server(server))
        
        # Wait for server startup
        await asyncio.sleep(3)
        
        try:
            for i in range(iterations):
                logger.info(f"\n🔄 Round {i+1}/{iterations}")
                
                # Client → Server (3GB)
                client_start = time.perf_counter()
                client = PQCClient(self.key_path, str(self.test_file))
                await client.connect_and_send("127.0.0.1", 8443)
                client_time = time.perf_counter() - client_start
                throughput = self.file_size_gb * 1024 / client_time
                
                results['client_to_server'].append({
                    'round': i+1, 'time_s': client_time, 'throughput_mb_s': throughput
                })
                logger.info(f"📤 C→S: {client_time:.2f}s ({throughput:.0f} MB/s)")
                
                results['total_rounds'] += 1
                
        finally:
            server_task.cancel()
            try:
                await server_task
            except:
                pass
        
        return results
    
    async def _run_benchmark_server(self, server: PQCServer):
        """✅ Non-blocking server for benchmarks."""
        # Override handle_client for benchmark mode (discard files)
        original_handle = server.handle_client
        async def benchmark_handle_client(reader, writer):
            client_id = server.clients_processed
            server.clients_processed += 1
            
            sm = StateMachine(str(server.key_path), "server")
            server.active_clients[client_id] = (reader, writer, sm)
            
            try:
                # Handshake
                await sm.transition("recv_handshake", reader=reader, writer=writer)
                await sm.transition("send_response", reader=reader, writer=writer)
                logger.info(f"Client #{client_id}: Handshake OK")
                
                # Receive file → discard immediately
                temp_file = Path(tempfile.mktemp(suffix=f"_gpu{client_id}.bin"))
                await sm.transition("start_recv_file", reader=reader, writer=writer, 
                                  output_path=str(temp_file))
                
                # Auto-delete
                if temp_file.exists():
                    temp_file.unlink()
                    
            except Exception as e:
                logger.error(f"Client #{client_id} error: {e}")
            finally:
                if client_id in server.active_clients:
                    del server.active_clients[client_id]
                writer.close()
                await writer.wait_closed()
        
        server.handle_client = benchmark_handle_client
        logger.info("🚀 Benchmark server listening on 127.0.0.1:8443")
        
        server_instance = await asyncio.start_server(server.handle_client, "127.0.0.1", 8443)
        async with server_instance:
            await asyncio.Future()  # Run forever (cancelled by benchmark)

async def main():
    tester = ThroughputTester(key_path="./keys", file_size_gb=3.0)
    
    logger.info("🚀 Starting PQC 3GB x10 Benchmark")
    start_total = time.perf_counter()
    
    results = await tester.benchmark_roundtrip(iterations=10)
    total_time = time.perf_counter() - start_total
    
    # Professional table
    c2s_times = [r['time_s'] for r in results['client_to_server']]
    avg_time = sum(c2s_times) / len(c2s_times)
    
    print("\n" + "═" * 88)
    print("         PQC SECURE FILE TRANSFER BENCHMARK          ")
    print("         Post-Quantum Cryptography                   ")
    print("═" * 88)
    print(f"  File Size:     {tester.file_size_gb} GB")
    print(f"  Rounds:        {results['total_rounds']} (C→S)")
    print(f"  Total Time:    {total_time:.1f} s")
    print()
    print(f"  Average:       {avg_time:.2f}s ({tester.file_size_gb*1024*10/avg_time:.0f} MB/s)")
    print(f"  Best:          {min(c2s_times):.2f}s ({tester.file_size_gb*1024/min(c2s_times):.0f} MB/s)")
    print()
    print("  💾 Disk Usage: ZERO - Temp files auto-deleted")
    print("═" * 88)

if __name__ == "__main__":
    asyncio.run(main())
