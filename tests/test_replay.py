#!/usr/bin/env python3
"""
StateMachine Integration Test
Tests complete client-server relay: handshake + bidirectional 50MB file transfer
"""

import asyncio
import os
import sys
import logging
from pathlib import Path
import tempfile
import secrets

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.dirname(__file__))

from kimura.protocol.state_machine import StateMachine, TransferState

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

def generate_50mb_file(filepath):
    """Generate 50MB binary file for transfer testing"""
    size_mb = 50
    target_size = size_mb * 1024 * 1024  # 50MB in bytes
    
    logger.info(f"Generating {size_mb}MB test file: {filepath}")
    with open(filepath, 'wb') as f:
        # Write identifiable pattern
        f.write(b'FL_ENCRYPT_50MB_TEST_FILE_HEADER_v1\n')
        # Fill with cryptographically random data (realistic model weights)
        while f.tell() < target_size:
            chunk_size = min(8192, target_size - f.tell())
            f.write(secrets.token_bytes(chunk_size))
    
    actual_size = os.path.getsize(filepath)
    logger.info(f"Generated {actual_size/1024/1024:.1f}MB file")

async def server_handler(reader, writer):
    """Server protocol implementation"""
    peer = writer.get_extra_info('peername')
    logger.info(f"Server accepted connection from {peer}")
    
    server_sm = StateMachine(os.path.join("keys", "server"), "server")
    
    try:
        # Handshake
        await server_sm.transition("recv_handshake", reader, writer)
        await server_sm.transition("send_response", reader, writer)
        logger.info("Server handshake complete")
        
        # Receive 50MB client file
        recv_path = Path(tempfile.gettempdir()) / f"server_recv_50mb_{id(writer)}.bin"
        await server_sm.transition("start_recv_file", reader, writer, 
                                 output_path=str(recv_path))
        recv_size = os.path.getsize(recv_path)
        logger.info(f"Server received 50MB file: {recv_size/1024/1024:.1f}MB")
        
        # Verify integrity (header + size)
        with open(recv_path, 'rb') as f:
            header = f.read(32)
            assert header.startswith(b'FL_ENCRYPT_50MB_TEST_FILE_HEADER_v1')
        
        # Send 50MB server file back
        send_path = Path("tests/server_50mb.bin")
        await server_sm.transition("start_send_file", reader, writer, 
                                 filepath=str(send_path))
        logger.info(f"Server sent 50MB file: {os.path.getsize(send_path)/1024/1024:.1f}MB")
        
    except Exception as e:
        logger.error(f"Server protocol error: {e}")
    finally:
        writer.close()
        await writer.wait_closed()

async def client_handler():
    """Client protocol implementation"""
    client_sm = StateMachine(os.path.join("keys", "client"), "client")
    
    reader, writer = await asyncio.open_connection('127.0.0.1', 8765)
    
    try:
        # Handshake
        await client_sm.transition("send_handshake", reader, writer)
        logger.info("Client handshake complete")
        
        # Send 50MB client file
        send_path = Path("tests/client_50mb.bin")
        await client_sm.transition("start_send_file", reader, writer, 
                                 filepath=str(send_path))
        logger.info(f"Client sent 50MB file: {os.path.getsize(send_path)/1024/1024:.1f}MB")
        
        # Receive 50MB server response
        recv_path = Path(tempfile.gettempdir()) / f"client_recv_50mb_{os.getpid()}.bin"
        await server_sm.transition("start_recv_file", reader, writer,
                                 output_path=str(recv_path))
        recv_size = os.path.getsize(recv_path)
        logger.info(f"Client received 50MB file: {recv_size/1024/1024:.1f}MB")
        
        # Verify integrity
        with open(recv_path, 'rb') as f:
            header = f.read(32)
            assert header.startswith(b'FL_ENCRYPT_50MB_TEST_FILE_HEADER_v1')
        
    except Exception as e:
        logger.error(f"Client protocol error: {e}")
    finally:
        writer.close()
        await writer.wait_closed()

async def test_relay():
    """Complete 50MB relay test"""
    # Pre-generate 50MB files
    Path("tests").mkdir(exist_ok=True)
    
    client_file = Path("tests/client_50mb.bin")
    server_file = Path("tests/server_50mb.bin")
    
    if not client_file.exists():
        generate_50mb_file(client_file)
    if not server_file.exists():
        generate_50mb_file(server_file)
    
    # Start server
    server = await asyncio.start_server(server_handler, '127.0.0.1', 8765)
    logger.info("Server listening on 127.0.0.1:8765")
    
    await asyncio.sleep(0.1)  # Server startup
    
    # Run client
    await client_handler()
    
    # Cleanup
    server.close()
    await server.wait_closed()
    
    logger.info("50MB relay test complete")

async def main():
    logger.info("StateMachine 50MB relay test starting")
    await test_relay()
    logger.info("Test passed")

if __name__ == "__main__":
    asyncio.run(main())
