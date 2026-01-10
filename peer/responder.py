#!/usr/bin/env python3
"""
Daemon: python3 -m peer.responder 0.0.0.0:12345
"""

import asyncio
import sys
from pathlib import Path
import sys
sys.path.insert(0, '..')

from transport.tcp import TCPServer
from peer.peer import PQCResponder

async def handle_client(reader, writer):
    """Handle single PQC client connection."""
    addr = writer.get_extra_info('peername')
    print(f"🔗 Client connected: {addr}")
    
    responder = PQCResponder("responder")
    output_dir = Path("downloads")
    output_dir.mkdir(exist_ok=True)
    
    try:
        await responder.run_protocol(reader, writer, output_dir=output_dir)
        print(f"✅ Transfer complete from {addr}")
    except Exception as e:
        print(f"❌ Client {addr} error: {e}")
    finally:
        writer.close()
        await writer.wait_closed()

async def main(host: str = "0.0.0.0", port: int = 12345):
    print(f"🚀 Starting PQC Responder on {host}:{port}")
    print("📁 Files will be saved to ./downloads/")
    
    # ✅ Uses transport/tcp.py context manager
    async with TCPServer(host, port, handle_client):
        await asyncio.Future()  # Run forever
        print("🛑 Server stopped")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        hostport = sys.argv[1].split(':')
        host, port = hostport[0], int(hostport[1])
    else:
        host, port = "0.0.0.0", 12345
    
    try:
        asyncio.run(main(host, port))
    except KeyboardInterrupt:
        print("\n👋 Responder stopped")
