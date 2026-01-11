# session/server.py
import asyncio
import logging
from .manager import SessionManager

class FederatedServer(SessionManager):
    def __init__(self, dataset: str, key_path: str):
        super().__init__("server", key_path)
        self.dataset = dataset
        self.clients_connected = 0
    
    async def run(self, port: int = 8443):
        await self.establish_channel()
        
        # Wait for clients
        while self.clients_connected < 10:  # Your cluster size
            await asyncio.sleep(1)
            logging.info(f"Waiting for clients... ({self.clients_connected}/10)")
        
        logging.info("✓ All 10 clients connected. Channel established.")
        await asyncio.sleep(2)  # Simulate transfer
