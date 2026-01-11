from enum import Enum, auto
from typing import Optional
import logging
import os
import sys
import asyncio
from pathlib import Path

# Fix imports for YOUR project structure
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.dirname(__file__))

from crypto.kdf import hkdf_sha256
from crypto.aead import AEADContext
from crypto.mlkem import MLKEM
from protocol.messages import (
    serialize_handshake_init, 
    parse_handshake_resp,
    serialize_handshake_resp,
    parse_handshake_init
)
from file_transfer.transfer import (
    send_length_prefixed,
    recv_length_prefixed,
    send_file,
    recv_file
)
from crypto.keygen import load_persistent_keys

logger = logging.getLogger(__name__)

class TransferState(Enum):
    INIT = auto()
    HANDSHAKE_SENT = auto()
    HANDSHAKE_RECV = auto()
    HANDSHAKE_COMPLETE = auto()
    FILE_TRANSFER = auto()
    TRANSFER_DONE = auto()
    ERROR = auto()

class ProtocolError(Exception):
    pass

class StateMachine:
    def __init__(self, key_path: str, role: str):
        self.state = TransferState.INIT
        self.role = role
        self.key_path = key_path
        self.session_key: Optional[bytes] = None
        self.aead_ctx: Optional[AEADContext] = None
        self.kem: Optional[MLKEM] = None
        self.kem_public_key: Optional[bytes] = None
        self.kem_secret_key: Optional[bytes] = None
        
        # LOAD YOUR PERSISTENT KEYS FROM ./keys/
        self.kem_public_key, self.kem_secret_key = load_persistent_keys(key_path)
        self.kem = MLKEM("ML-KEM-768")

    async def transition(self, event: str, reader=None, writer=None, **kwargs) -> None:
        """🚀 MAIN FUNCTION: Call this from manager.py with event strings."""
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
            TransferState.HANDSHAKE_COMPLETE: {
                "start_send_file": self._start_send_file,
                "start_recv_file": self._start_recv_file,
            },
        }
        
        if self.state not in transitions or event not in transitions[self.state]:
            self._error(f"Invalid transition: {self.state.name} + {event}")
            return
        
        await transitions[self.state][event](reader, writer, **kwargs)

    async def _client_send_handshake(self, reader, writer, **kwargs):
        """CLIENT: Send OWN ML-KEM public key (loaded from keys/)."""
        handshake_msg = serialize_handshake_init(self.kem_public_key)
        await send_length_prefixed(writer, handshake_msg)
        self.state = TransferState.HANDSHAKE_SENT
        logger.info("✅ CLIENT: PK sent")

    async def _server_recv_handshake(self, reader, writer, **kwargs):
        """SERVER: Receive CLIENT's ML-KEM public key."""
        handshake_msg = await recv_length_prefixed(reader)
        self.kem_public_key = parse_handshake_init(handshake_msg)  # Store CLIENT PK
        self.state = TransferState.HANDSHAKE_RECV
        logger.info("✅ SERVER: Client PK received")

    async def _client_recv_response(self, reader, writer, **kwargs):
        """CLIENT: Receive server ML-KEM ciphertext → derive session key."""
        resp = await recv_length_prefixed(reader)
        ciphertext = parse_handshake_resp(resp)
        shared_secret = self.kem.decaps(ciphertext, self.kem_secret_key)
        self.session_key = hkdf_sha256(shared_secret, b"", b"pqc_session_v1", 32)
        self.aead_ctx = AEADContext(self.session_key)
        self.state = TransferState.HANDSHAKE_COMPLETE
        logger.info("✅ CLIENT: PQC handshake complete!")

    async def _server_send_response(self, reader, writer, **kwargs):
        """SERVER: Encapsulate using CLIENT's PK → send ciphertext."""
        ciphertext, shared_secret = self.kem.encaps(self.kem_public_key)
        self.session_key = hkdf_sha256(shared_secret, b"", b"pqc_session_v1", 32)
        self.aead_ctx = AEADContext(self.session_key)
        
        resp_msg = serialize_handshake_resp(ciphertext)
        await send_length_prefixed(writer, resp_msg)
        self.state = TransferState.HANDSHAKE_COMPLETE
        logger.info("✅ SERVER: PQC handshake complete!")

    async def _start_send_file(self, reader, writer, filepath: str):
        """CLIENT: Start encrypted file transfer (uses your transfer.py)."""
        if not self.aead_ctx:
            self._error("No AEAD context")
        await send_file(writer, Path(filepath), self.aead_ctx)
        logger.info("✅ CLIENT: File sent")

    async def _start_recv_file(self, reader, writer, output_path: str):
        """SERVER: Receive encrypted file (uses your transfer.py)."""
        if not self.aead_ctx:
            self._error("No AEAD context")
        await recv_file(reader, writer, Path(output_path), self.aead_ctx)
        logger.info("✅ SERVER: File received")

    def _error(self, reason: str):
        self.state = TransferState.ERROR
        raise ProtocolError(reason)

    def is_ready_for_transfer(self) -> bool:
        return self.state == TransferState.HANDSHAKE_COMPLETE and self.aead_ctx is not None
    def get_aead_context(self) -> AEADContext:
        if not self.aead_ctx:
            self._error("AEAD context not initialized")
        return self.aead_ctx