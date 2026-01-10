#!/usr/bin/env python3
"""
CLI: python3 -m peer.initiator 127.0.0.1:12345 model.pt
"""

import asyncio
import sys
from pathlib import Path
import sys
sys.path.insert(0, '..')

from transport.tcp import TCPConnection
from peer.peer import PQCInitiator

async def main():
    if len(sys.argv) != 3:
        print("Usage: python3 -m peer.initiator host:port file")
        print("Example: python3 -m peer.initiator 127.0.0.1:12345 model.pt")
        return
    
    hostport, filepath = sys.argv[1], sys.argv[2]
    host, port = hostport.split(':')
    port = int(port)
    
    filepath = Path(filepath)
    if not filepath.exists():
        print(f"❌ File not found: {filepath}")
        return
    
    print(f"🚀 Sending {filepath} to {host}:{port}")
    
    # ✅ Uses transport/tcp.py context manager
    async with TCPConnection(host, port) as (reader, writer):
        initiator = PQCInitiator("initiator")
        await initiator.run_protocol(reader, writer, filepath=filepath)
    
    print("✅ Transfer complete!")

if __name__ == "__main__":
    asyncio.run(main())
