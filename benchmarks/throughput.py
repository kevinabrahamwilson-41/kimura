#!/usr/bin/env python3
import asyncio
import time
import sys
import os
from pathlib import Path
import tempfile
import logging
from kimura.protocol.state_machine import StateMachine, ProtocolError
from kimura.protocol.constants import DEFAULT_PORT
from kimura.file_transfer.transfer import chunked_send_file, recv_file

PROJECT_ROOT = Path(__file__).parent.parent.absolute()
sys.path.insert(0, str(PROJECT_ROOT))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-5s %(message)s")
log = logging.getLogger("pqc_benchmark")

class PQCBenchmark:
    def __init__(self, key_path="./keys", file_size_gb=0.1,compressible=False):
        self.key_path = key_path
        self.file_size_gb = file_size_gb
        self.compressible = compressible
        self.file_size_bytes = int(file_size_gb * 1024**3)
        self.test_file = self._create_test_file()
    
    def _create_test_file(self):
        name = "compressible.bin"
        path = Path(name)

        if path.exists() and path.stat().st_size >= self.file_size_bytes:
            return path

        log.info(f"Creating {self.file_size_gb}GB test file (compressible={self.compressible})")

        with open(path, "wb") as f:
            chunk = 64 * 1024 * 1024  # 64MB
            written = 0

            if self.compressible:
                pattern = b"HELLO_WORLD\n" * 1024  # repeated pattern
                while written < self.file_size_bytes:
                    size = min(len(pattern), self.file_size_bytes - written)
                    f.write(pattern[:size])
                    written += size
            else:
                while written < self.file_size_bytes:
                    size = min(chunk, self.file_size_bytes - written)
                    f.write(os.urandom(size))
                    written += size

        return path
    
    # === RAW TCP BASELINE ===
    async def raw_tcp_test(self):
        start = time.perf_counter()
        reader, writer = await asyncio.open_connection("127.0.0.1", DEFAULT_PORT)
        
        # Send file size (8 bytes)
        file_size = self.test_file.stat().st_size
        writer.write(file_size.to_bytes(8, 'big'))
        await writer.drain()
        
        # Send file chunks
        with open(self.test_file, "rb") as f:
            while chunk := f.read(10 * 1024 * 1024):  # 10MB chunks
                writer.write(chunk)
                await writer.drain()
        
        writer.close()
        await writer.wait_closed()
        duration = time.perf_counter() - start
        
        mbps = (file_size / 1024**2) / duration
        return {
            "mode": "RAW_TCP", 
            "bytes": file_size,
            "duration_ms": duration * 1000,
            "throughput_mbps": mbps,
            "time_ms": duration * 1000
        }
    
    # === PQC ENCRYPTED TEST ===
    async def pqc_encrypted_test(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", DEFAULT_PORT)
        sm = StateMachine(self.key_path, "client")
        
        t_start = time.perf_counter()
        
        # 1. Full MLKEM/MLDSA handshake
        await sm.transition("send_handshake", reader=reader, writer=writer)
        
        # 2. Send test file via your chunked AEAD
        await sm.transition("start_send_file", 
                           reader=reader, 
                           writer=writer, 
                           filepath=str(self.test_file))
        
        t_end = time.perf_counter()
        
        writer.close()
        await writer.wait_closed()
        
        file_size = self.test_file.stat().st_size
        duration_ms = (t_end - t_start) * 1000
        
        return {
            "mode": "PQC_ENCRYPTED", 
            "bytes": file_size,
            "duration_ms": duration_ms,
            "throughput_mbps": (file_size / 1024**2) / (duration_ms / 1000),
            "handshake_ms": 0  # Add timing inside StateMachine if needed
        }
    
    # === RAW SERVER ===
    async def _raw_server(self):
        async def handle_raw(reader, writer):
            # Read file size
            file_size = int.from_bytes(await reader.readexactly(8), 'big')
            received = 0
            with open("raw_received.bin", "wb") as f:
                while received < file_size:
                    chunk = await reader.read(128*1024)
                    if not chunk:
                        break
                    f.write(chunk)
                    received += len(chunk)
            log.info(f"RAW server received {received/1024**2:.1f}MB")
            writer.close()
            await writer.wait_closed()
        
        server = await asyncio.start_server(handle_raw, "127.0.0.1", DEFAULT_PORT)
        log.info("RAW server listening...")
        async with server:
            await asyncio.Future()
    
    # === PQC SERVER ===
    async def _pqc_server(self):
        async def handle_pqc(reader, writer):
            sm = StateMachine(self.key_path, "server")
            try:
                # Handshake
                await sm.transition("recv_handshake", reader=reader, writer=writer)
                await sm.transition("send_response", reader=reader, writer=writer)
                
                # Receive file
                with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
                    temp_path = tmp.name
                
                await sm.transition("start_recv_file", 
                                   reader=reader, 
                                   writer=writer, 
                                   output_path=temp_path,
                                   use_lz4=True)
                
                file_size = Path(temp_path).stat().st_size
                log.info(f"PQC server received {file_size/1024**2:.1f}MB")
                os.unlink(temp_path)
                
            except Exception as e:
                log.error(f"PQC server error: {e}")
            finally:
                writer.close()
                await writer.wait_closed()
        
        server = await asyncio.start_server(handle_pqc, "127.0.0.1", DEFAULT_PORT)
        log.info("PQC server listening...")
        async with server:
            await asyncio.Future()
    
    async def run(self, iterations=5, file_gb=0.1):
        self.file_size_gb = file_gb
        self.test_file.unlink(missing_ok=True)
        self.test_file = self._create_test_file()
        
        all_results = []
        
        # === RAW TCP ===
        log.info("=== RAW TCP BENCHMARK ===")
        raw_server = asyncio.create_task(self._raw_server())
        await asyncio.sleep(1)
        
        raw_results = []
        for i in range(iterations):
            log.info(f"RAW round {i+1}")
            result = await self.raw_tcp_test()
            raw_results.append(result)
            log.info(f"RAW: {result['throughput_mbps']:.1f} MB/s ({result['duration_ms']:.0f}ms)")
        
        raw_server.cancel()
        all_results.extend(raw_results)
        
        await asyncio.sleep(1)
        
        # === PQC ENCRYPTED ===
        log.info("\n=== PQC ENCRYPTED BENCHMARK ===")
        pqc_server = asyncio.create_task(self._pqc_server())
        await asyncio.sleep(1)
        
        pqc_results = []
        for i in range(iterations):
            log.info(f"PQC round {i+1}")
            result = await self.pqc_encrypted_test()
            pqc_results.append(result)
            log.info(f"PQC: {result['throughput_mbps']:.1f} MB/s ({result['duration_ms']:.0f}ms)")
        
        pqc_server.cancel()
        all_results.extend(pqc_results)
        
        self._print_summary(raw_results, pqc_results)
        return all_results
    
    def _print_summary(self, raw_results, pqc_results):
        print("\n" + "="*70)
        print("PQC LIBRARY THROUGHPUT BENCHMARK")
        print("="*70)
        print(f"{'MODE':<15} {'AVG MB/s':<10} {'BEST MB/s':<10} {'AVG TIME':<12} {'OVERHEAD':<10}")
        print("-"*70)
        
        raw_avg = sum(r['throughput_mbps'] for r in raw_results) / len(raw_results)
        raw_best = max(r['throughput_mbps'] for r in raw_results)
        raw_time = sum(r['duration_ms'] for r in raw_results) / len(raw_results)
        
        pqc_avg = sum(r['throughput_mbps'] for r in pqc_results) / len(pqc_results)
        pqc_best = max(r['throughput_mbps'] for r in pqc_results)
        pqc_time = sum(r['duration_ms'] for r in pqc_results) / len(pqc_results)
        
        overhead = ((raw_avg - pqc_avg) / raw_avg) * 100
        
        print(f"{'RAW TCP':<15} {raw_avg:<10.1f} {raw_best:<10.1f} {raw_time:<12.0f}ms {'-':<10}")
        print(f"{'PQC ENCRYPTED':<15} {pqc_avg:<10.1f} {pqc_best:<10.1f} {pqc_time:<12.0f}ms {overhead:<7.1f}%")
        print(f"{'OVERHEAD':<15} {(raw_avg-pqc_avg):<10.1f} {'-':<10} {'-':<12} {'':<10}")
        print("="*70)

async def main():
    benchmark = PQCBenchmark(key_path="./keys", file_size_gb=0.05)  # 50MB
    await benchmark.run(iterations=3)

if __name__ == "__main__":
    asyncio.run(main())
