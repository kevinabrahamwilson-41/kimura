# session/manager.py - COMPLETE flow w/ your tcp.py
import asyncio
import logging
from pathlib import Path
from transport.tcp import TCPTransport
from protocol.state_machine import StateMachine

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(message)s")
logger = logging.getLogger(__name__)

class SessionManager:
    def __init__(self, role: str, key_path: str = "./keys", output_path: str = None):
        self.role = role
        self.key_path = Path(key_path)
        self.state_machine = StateMachine(str(self.key_path), self.role)
        self.reader = None
        self.writer = None
        self.output_path = output_path
        self.transport = TCPTransport()
        self.ready = asyncio.Event()
    
    async def establish_channel(self):
        """PHASE 1: PQC Handshake → Store reader/writer for file transfer."""
        if self.role == "client":
            await self._client_handshake()
        else:
            await self._server_handshake()
        
        logger.info("✅ PQC Handshake DONE - Ready for file transfer!")
        logger.info(f"State: {self.state_machine.state.name}")
        self.ready.set()
    
    async def _client_handshake(self):
        """CLIENT: Connect → Send PK → Recv CT."""
        self.reader, self.writer = await self.transport.connect("127.0.0.1", 8443)
        
        await self.state_machine.transition("send_handshake", 
                                          reader=self.reader, writer=self.writer)
        await self.state_machine.transition("recv_response", 
                                          reader=self.reader, writer=self.writer)
        
    async def _server_handshake(self):
        """SERVER: SINGLE connection - handshake + receive file in SAME handler."""
        async def handler(reader, writer):
            self.reader, self.writer = reader, writer  # Store connection!
            try:
                logger.info("✅ SERVER: Client connected!")
                # 1️⃣ PQC Handshake
                await self.state_machine.transition("recv_handshake", reader, writer)
                await self.state_machine.transition("send_response", reader, writer)
                logger.info("✅ SERVER: PQC handshake complete!")
                
                # 2️⃣ RECEIVE FILE IN SAME HANDLER (NO DEADLOCK!)
                await self.state_machine.transition("start_recv_file", 
                                                reader=reader, 
                                                writer=writer, 
                                                output_path = self.output_path)
                logger.info("✅ SERVER: File transfer complete!")
                
            except Exception as e:
                logger.error(f"❌ Server error: {e}")
            finally:
                writer.close()
                await writer.wait_closed()
        
        server = await self.transport.serve("0.0.0.0", 8443, handler)
        logger.info("🚀 Server listening on 0.0.0.0:8443 - waiting for client...")
        async with server:
            await asyncio.Future()  # Run forever

    async def send_file(self, filepath: str):
        """PHASE 2: Send file over EXISTING connection."""
        if not self.state_machine.is_ready_for_transfer():
            raise RuntimeError("Must call establish_channel() first!")
        
        await self.state_machine.transition("start_send_file", 
                                          reader=self.reader,
                                          writer=self.writer,
                                          filepath=filepath)
        logger.info(f"✅ Sent: {filepath}")
    
    async def recv_file(self, output_path: str):
        """PHASE 2: Receive file over EXISTING connection."""
        if not self.state_machine.is_ready_for_transfer():
            raise RuntimeError("Must call establish_channel() first!")
        
        await self.state_machine.transition("start_recv_file", 
                                          reader=self.reader,
                                          writer=self.writer,
                                          output_path=output_path)
        logger.info(f"✅ Received: {output_path}")
    
    async def close(self):
        if self.writer:
            await self.transport.safe_close(self.writer)

# 🔥 TEST IT
async def test_full_flow():
    """Terminal 1: Server first"""
    server_mgr = SessionManager("server")
    await server_mgr.establish_channel()  # Waits for client
    await server_mgr.recv_file("received_model.pt")
    
    """Terminal 2: Client second"""
    client_mgr = SessionManager("client")
    await client_mgr.establish_channel()  # Connects + handshakes
    await client_mgr.send_file("my_model.pt")  # Your PyTorch model

if __name__ == "__main__":
    asyncio.run(test_full_flow())
