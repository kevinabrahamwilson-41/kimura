# session/server.py
import asyncio
import logging
from pathlib import Path
from .manager import SessionManager

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PQCServer:
    def __init__(self, key_path: str, base_output: str):
        self.key_path = Path(key_path)
        self.base_output = Path(base_output)
        self.clients_processed = 0
        
    async def handle_client(self, reader, writer):
        """Handle each GPU client connection"""
        client_count = self.clients_processed
        output_file = f"{self.base_output.stem}_gpu{client_count}.bin"
        
        logger.info(f"🎯 GPU Client #{client_count} connected from {writer.get_extra_info('peername')}")
        
        # Create NEW task for this client - let SessionManager do its thing
        client_task = asyncio.create_task(
            self._process_client(client_count, str(output_file), reader, writer)
        )
        
        try:
            await client_task
        except Exception as e:
            logger.error(f"❌ GPU Client #{client_count} error: {e}")
        finally:
            self.clients_processed += 1
            writer.close()
            await writer.wait_closed()
            logger.info(f"🚀 Server ready for GPU client #{self.clients_processed + 1}")


    async def serve_forever(self, port: int = 8443, host: str = "0.0.0.0"):
        """Single server handling unlimited clients"""
        print(f"🚀 DISTRIBUTED PQC SERVER @ {host}:{port} - Unlimited GPU nodes!")
        
        server = await asyncio.start_server(
            self.handle_client, host, port
        )
        
        print(f"✅ TCP Server listening on ({host}, {port})")
        async with server:
            await server.serve_forever()

    async def _process_client(self, client_id: int, output_file: str, reader, writer):
        """Spawn isolated SessionManager for each client"""
        mgr = SessionManager("server", str(self.key_path), output_file)
        
        # Monkey patch transport - SessionManager will use these
        mgr._reader = reader  
        mgr._writer = writer
        
        await mgr.establish_channel()  # Now works properly
        await mgr.recv_file(output_file)