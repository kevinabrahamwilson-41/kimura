# peer/peer.py - Base PQC peer
"""
Common base for initiator/responder. Manages protocol/state_machine.
"""

import asyncio
import logging
from pathlib import Path
import sys
sys.path.insert(0, '..')

from protocol.state_machine import StateMachine
from protocol.messages import *
from file_transfer.transfer import send_file, recv_file
from crypto.mlkem import MLKEM

class PQCPeer:
    def __init__(self, role: str):
        self.role = role  # "initiator" or "responder"
        self.sm = StateMachine(role)
    
    async def run_protocol(self, reader, writer, **kwargs):
        """Execute full PQC protocol."""
        raise NotImplementedError

class PQCInitiator(PQCPeer):
    """File sender - initiates handshake."""
    
    async def run_protocol(self, reader, writer, filepath: Path):
        """Full initiator protocol flow."""
        # 1. PQC Handshake
        self.sm.transition("send_handshake", reader=reader, writer=writer)
        await asyncio.sleep(0.1)  # Let handshake complete
        
        self.sm.transition("recv_response", reader=reader, writer=writer)
        await asyncio.sleep(0.1)
        
        # 2. Send file using YOUR file_transfer/
        if self.sm.is_ready_for_transfer():
            self.sm.transition("start_send_file", reader=reader, writer=writer, filepath=str(filepath))
        else:
            raise RuntimeError("Handshake failed")
        
        await writer.drain()
        print("✅ File sent!")

class PQCResponder(PQCPeer):
    """File receiver - responds to handshake."""
    
    async def run_protocol(self, reader, writer, output_dir: Path):
        """Full responder protocol flow."""
        # 1. Receive handshake → respond
        self.sm.transition("recv_handshake", reader=reader, writer=writer)
        await asyncio.sleep(0.1)
        
        self.sm.transition("send_response", reader=reader, writer=writer) 
        await asyncio.sleep(0.1)
        
        # 2. Receive file using YOUR file_transfer/
        output_path = output_dir / f"received_{asyncio.get_event_loop().time():.0f}.bin"
        if self.sm.is_ready_for_transfer():
            self.sm.transition("start_recv_file", reader=reader, writer=writer, output_path=str(output_path))
        else:
            raise RuntimeError("Handshake failed")
        
        print(f"✅ File saved: {output_path}")
