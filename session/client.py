# session/client.py
import asyncio
from pathlib import Path
from .manager import SessionManager

class PQCClient:
    def __init__(self, key_path: str, file_path: str):
        self.key_path = Path(key_path)
        self.file_path = Path(file_path)
        
    async def connect_and_send(self, host: str, port: int = 8443):
        """Connect to PQC server and send file"""
        print(f"🚀 PQC Client connecting to {host}:{port}...")
        
        try:
            # Create SessionManager for this connection
            mgr = SessionManager("client", str(self.key_path), str(self.file_path))
            
            # Connect and do full PQC handshake + file transfer
            await mgr.establish_channel(host, port)
            await mgr.send_file(str(self.file_path))
            print(f"✅ CLIENT: '{self.file_path.name}' sent successfully!")
            
        except Exception as e:
            print(f"❌ Client error: {e}")
        finally:
            await mgr.close()
