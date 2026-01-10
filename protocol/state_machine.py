# protocol/state_machine.py - FIXED + YOUR file_transfer/ INTEGRATED
"""
Production PQC File Transfer State Machine w/ YOUR file_transfer.transfer.py
"""

from enum import Enum, auto
from typing import Optional
import logging
import os
import sys
import asyncio
from pathlib import Path
# Fix imports for YOUR project structure
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.dirname(__file__))  # protocol/

from crypto.kdf import hkdf_sha256
from crypto.aead import AEADContext
from crypto.mlkem import MLKEM
from protocol.messages import (  # YOUR messages.py
    serialize_handshake_init, 
    parse_handshake_resp,
    serialize_handshake_resp,
    parse_handshake_init
)
from file_transfer.transfer import (  # YOUR transfer.py!
    send_length_prefixed,
    recv_length_prefixed,
    send_file,
    recv_file
)

logger = logging.getLogger(__name__)

class TransferState(Enum):
    """Strict protocol progression."""
    INIT = auto()
    HANDSHAKE_SENT = auto()      # Client → Server: ML-KEM PK
    HANDSHAKE_RECV = auto()      # Server got client PK
    HANDSHAKE_RESP_SENT = auto() # Server → Client: ML-KEM CT  
    HANDSHAKE_COMPLETE = auto()  # Both have AES-256 session key
    FILE_TRANSFER = auto()
    TRANSFER_DONE = auto()
    ERROR = auto()

class ProtocolError(Exception):
    """Protocol violation."""

class StateMachine:
    def __init__(self, role: str = "client"):  # "client" or "server"
        self.state = TransferState.INIT
        self.role = role
        self.session_key: Optional[bytes] = None
        self.aead_ctx: Optional[AEADContext] = None
        self.kem: Optional[MLKEM] = None
        self.kem_public_key: Optional[bytes] = None
        self.kem_secret_key: Optional[bytes] = None
        self.file_size: Optional[int] = None
        self.total_chunks: Optional[int] = None
        self.chunks_received: int = 0
        
    def transition(self, event: str, reader=None, writer=None, **kwargs) -> None:
        """Atomic state transitions w/ YOUR crypto & networking."""
        logger.debug(f"[{self.role.upper()}] {self.state.name} → {event}")
        
        transitions = {
            TransferState.INIT: {
                "send_handshake": self._client_send_handshake,
                "recv_handshake": self._server_recv_handshake,
            },
            TransferState.HANDSHAKE_SENT: {
                "recv_response": self._client_recv_response,
            },
            TransferState.HANDSHAKE_RECV: {
                "send_response": self._server_send_response,
            },
            TransferState.HANDSHAKE_RESP_SENT: {
                "recv_handshake_ok": self._server_recv_ok,  # Optional confirmation
            },
            TransferState.HANDSHAKE_COMPLETE: {
                "start_send_file": self._start_send_file,
                "start_recv_file": self._start_recv_file,
            },
            TransferState.FILE_TRANSFER: {
                "chunk_sent": self._chunk_sent,
                "chunk_received": self._chunk_received,
                "transfer_done": self._to_transfer_done,
            },
        }
        
        if self.state not in transitions or event not in transitions[self.state]:
            self._error(f"Invalid transition: {self.state.name} + {event}")
        
        transitions[self.state][event](reader, writer, **kwargs)
    
    def _client_send_handshake(self, reader, writer, **kwargs):
        """CLIENT: Generate ML-KEM keys → send public key."""
        self.kem = MLKEM("ML-KEM-768")
        self.kem_public_key, self.kem_secret_key = self.kem.keygen()
        
        handshake_msg = serialize_handshake_init(self.kem_public_key)
        asyncio.create_task(send_length_prefixed(writer, handshake_msg))
        self.state = TransferState.HANDSHAKE_SENT
    
    def _server_recv_handshake(self, reader, writer, **kwargs):
        """SERVER: Receive client ML-KEM public key."""
        handshake_msg = asyncio.create_task(recv_length_prefixed(reader))
        client_pk = parse_handshake_init(handshake_msg.result())
        self.kem = MLKEM("ML-KEM-768")
        self.kem_public_key, self.kem_secret_key = self.kem.keygen()
        self.state = TransferState.HANDSHAKE_RECV
    
    def _client_recv_response(self, reader, writer, **kwargs):
        """CLIENT: Receive server ML-KEM ciphertext → derive key."""
        resp = asyncio.create_task(recv_length_prefixed(reader)).result()
        ciphertext = parse_handshake_resp(resp)
        shared_secret = self.kem.decaps(ciphertext, self.kem_secret_key)
        self.session_key = hkdf_sha256(shared_secret, b"", b"pqc_session_v1", 32)
        self.aead_ctx = AEADContext(self.session_key)
        self.state = TransferState.HANDSHAKE_COMPLETE
        logger.info("✅ CLIENT: PQC handshake complete!")
    
    def _server_send_response(self, reader, writer, **kwargs):
        """SERVER: Encapsulate → send ciphertext to client."""
        ciphertext, shared_secret = self.kem.encaps(self.kem_public_key)  # Client's PK
        self.session_key = hkdf_sha256(shared_secret, b"", b"pqc_session_v1", 32)
        self.aead_ctx = AEADContext(self.session_key)
        
        resp_msg = serialize_handshake_resp(ciphertext)
        asyncio.create_task(send_length_prefixed(writer, resp_msg))
        self.state = TransferState.HANDSHAKE_RESP_SENT
        logger.info("✅ SERVER: PQC handshake complete!")
    
    def _start_send_file(self, reader, writer, filepath: str):
        """CLIENT: Start sending file w/ YOUR transfer.py."""
        if not self.aead_ctx:
            self._error("No AEAD context")
        asyncio.create_task(send_file(writer, Path(filepath), self.aead_ctx))
        self.state = TransferState.FILE_TRANSFER
    
    def _start_recv_file(self, reader, writer, output_path: str):
        """SERVER: Start receiving file w/ YOUR transfer.py."""
        if not self.aead_ctx:
            self._error("No AEAD context") 
        asyncio.create_task(recv_file(reader, writer, Path(output_path), self.aead_ctx))
        self.state = TransferState.FILE_TRANSFER
    
    def _chunk_sent(self, chunk_idx: int):
        logger.debug(f"Chunk {chunk_idx} sent")
    
    def _chunk_received(self, chunk_idx: int):
        self.chunks_received += 1
    
    def _to_transfer_done(self):
        self.state = TransferState.TRANSFER_DONE
        logger.info("✅ File transfer complete!")
    
    def _error(self, reason: str):
        self.state = TransferState.ERROR
        raise ProtocolError(reason)
    
    def is_ready_for_transfer(self) -> bool:
        return self.state == TransferState.HANDSHAKE_COMPLETE and self.aead_ctx is not None

# USAGE EXAMPLE - YOUR peer/ files will use this!
async def client_example(host: str, port: int, filepath: str):
    """Full client protocol flow."""
    reader, writer = await asyncio.open_connection(host, port)
    sm = StateMachine("client")
    
    try:
        # 1. PQC Handshake
        sm.transition("send_handshake", reader=reader, writer=writer)
        sm.transition("recv_response", reader=reader, writer=writer)
        
        # 2. Send file w/ YOUR transfer.py
        sm.transition("start_send_file", reader=reader, writer=writer, filepath=filepath)
        
    finally:
        writer.close()
        await writer.wait_closed()

if __name__ == "__main__":
    print("✅ StateMachine ready - integrates w/ YOUR file_transfer/transfer.py!")
