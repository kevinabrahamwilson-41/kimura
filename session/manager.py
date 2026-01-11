# session/manager.py - COMPLETE flow w/ your tcp.py
import asyncio
import logging
from pathlib import Path
from file_transfer.transfer import send_length_prefixed
from protocol.messages import serialize_handshake_init
from transport.tcp import TCPTransport
from protocol.state_machine import StateMachine

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(message)s")
logger = logging.getLogger(__name__)

class SessionManager:
    def __init__(self, role: str, key_path: str = "./keys", output_path: str = None):
        self.role = role
        self.key_path = key_path
        self.output_path = output_path
        self.ready = asyncio.Event()
        self.state_machine = StateMachine(key_path, role)
        self.transport = TCPTransport()
        self.server_running = False
        self.active_clients = {}  # {client_id: (reader, writer, state_machine)}
        self.client_counter = 0
    
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
        """CLIENT: Send handshake via StateMachine (handles signing automatically)."""
        self.reader, self.writer = await self.transport.connect("127.0.0.1", 8443)
        
        # 🔥 STATE MACHINE DOES SIGNING INTERNALLY - Just call transition!
        await self.state_machine.transition("send_handshake", 
                                        reader=self.reader, 
                                        writer=self.writer)
        
        await self.state_machine.transition("recv_response", 
                                        reader=self.reader, 
                                        writer=self.writer)
        logger.info("✅ CLIENT: Signed handshake complete!")

    async def _server_handshake(self):
        async def handler(reader, writer):
            client_id = self.client_counter
            self.client_counter += 1

            client_sm = StateMachine(self.key_path, "server")
            self.active_clients[client_id] = (reader, writer, client_sm)

            try:
                logger.info(f"✅ GPU Client #{client_id} connected!")

                # Handshake is PER-CLIENT
                await client_sm.transition("recv_handshake", reader=reader, writer=writer)
                await client_sm.transition("send_response", reader=reader, writer=writer)

                logger.info(f"✅ GPU Client #{client_id}: PQC handshake complete!")

                # ONLY NOW mark server as ready
                self.ready.set()

            except Exception as e:
                logger.error(f"❌ GPU Client #{client_id} error: {e}")
                writer.close()
                await writer.wait_closed()
                del self.active_clients[client_id]

        self.server = await self.transport.serve("0.0.0.0", 8443, handler)
        self.server_running = True
        logger.info("🚀 PQC SERVER LISTENING @ 0.0.0.0:8443")
        await self.ready.wait()

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
        if not self.active_clients:
            raise RuntimeError("No connected clients")

        # Pick first connected client (or add selection logic)
        client_id, (reader, writer, sm) = next(iter(self.active_clients.items()))

        if not sm.is_ready_for_transfer():
            raise RuntimeError("Handshake incomplete for client")

        await sm.transition(
            "start_recv_file",
            reader=reader,
            writer=writer,
            output_path=output_path
        )

        logger.info(f"✅ SERVER: File received from client #{client_id}")

    async def close(self):
        logger.info("🧹 SessionManager shutting down...")

        # 1. Close all active client connections
        for client_id, (reader, writer, sm) in list(self.active_clients.items()):
            try:
                if writer:
                    writer.close()
                    await writer.wait_closed()
                    logger.info(f"🔌 Closed client #{client_id}")
            except Exception as e:
                logger.warning(f"⚠️ Error closing client #{client_id}: {e}")

        self.active_clients.clear()

        # 2. Close single writer if exists (client side or last server client)
        try:
            if hasattr(self, "writer") and self.writer:
                self.writer.close()
                await self.writer.wait_closed()
                self.writer = None
        except Exception as e:
            logger.warning(f"⚠️ Error closing main writer: {e}")

        # 3. Close the server socket (THIS IS THE KEY FIX)
        if hasattr(self, "server") and self.server:
            logger.info("🛑 Closing asyncio server...")
            self.server.close()
            await self.server.wait_closed()
            self.server = None
            self.server_running = False
            logger.info("✅ Server socket fully released")

        # 4. Reset readiness
        if self.ready:
            self.ready.clear()

        logger.info("✅ SessionManager cleanup complete")


async def test_full_flow():
    """🚨 FOR TESTING - Run in SEPARATE TERMINALS!"""
    # ===========================================
    # TERMINAL 1: SERVER (run first)
    # ===========================================
    print("🖥️  TERMINAL 1: Starting SERVER...")
    server_mgr = SessionManager("server", output_path="received_model.pt")
    # Server: Handshake ONLY (signatures handled automatically)
    await server_mgr.establish_channel()  # Waits for client + signed handshake
    print("✅ SERVER: Signed handshake complete! Ready for file...")
    # Receive signed file (hash+sig+encrypted_file)
    await server_mgr.recv_file("received_model.pt")
    print("✅ SERVER: Verified file received!")
    # ===========================================
    # TERMINAL 2: CLIENT (run SECOND)  
    # ===========================================
    print("💻 TERMINAL 2: Starting CLIENT...")
    client_mgr = SessionManager("client")
    # Client: Connect + signed handshake
    await client_mgr.establish_channel()  # Signed PK exchange + verification
    print("✅ CLIENT: Signed handshake complete!")
    # Send signed file (hash+sig+encrypted_file)
    await client_mgr.send_file("model.bin")  # Replace with real file
    print("✅ CLIENT: Signed file sent!")


if __name__ == "__main__":
    asyncio.run(test_full_flow())
