# session/client.py
import asyncio
import logging
from .manager import SessionManager

class FederatedClient(SessionManager):
    def __init__(self, gpu_id: int, key_path: str):
        super().__init__("client", key_path)
        self.gpu_id = gpu_id
    
    async def run(self, host: str):
        await self.establish_channel()
        
        # Training loop
        while True:
            logging.info(f"Round X/100: Received model, training on GPU {self.gpu_id}...")
            await asyncio.sleep(5)  # Simulate local training
