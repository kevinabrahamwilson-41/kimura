#!/usr/bin/env python3
import asyncio
import argparse
import sys
from pathlib import Path

# Keygen command FIRST
from crypto.keygen import generate_persistent_keys

async def main():
    parser = argparse.ArgumentParser("pqc-session", description="PQC Secure File Transfer")
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # 1. KEYGEN COMMAND (KEEP EXISTING)
    kg_parser = subparsers.add_parser("keygen", help="Generate ML-KEM keys")
    kg_parser.add_argument("--name", default="pqc", help="Key name prefix (default: pqc)")
    kg_parser.add_argument("--role", default="server", choices=["server", "client"], 
                          help="Key role (default: server)")
    
    # 🔥 2. NEW PQC TRANSFER COMMANDS
    transfer_parser = subparsers.add_parser("transfer", help="PQC file transfer")
    transfer_subparsers = transfer_parser.add_subparsers(dest="mode", help="Transfer mode")
    
    # SERVER MODE
    server_parser = transfer_subparsers.add_parser("server", help="Receive file")
    server_parser.add_argument("--port", type=int, default=8443)
    server_parser.add_argument("--output", required=True, help="Output file path")
    server_parser.add_argument("--key-path", default="./keys", help="Path to keys/")
    
    # CLIENT MODE  
    client_parser = transfer_subparsers.add_parser("client", help="Send file")
    client_parser.add_argument("host", help="server:port (ex: 127.0.0.1:8443)")
    client_parser.add_argument("--file", required=True, help="File to send")
    client_parser.add_argument("--key-path", default="./keys", help="Path to keys/")
    
    args = parser.parse_args()
    
    # HANDLE KEYGEN (sync, no asyncio)
    if args.command == "keygen":
        generate_persistent_keys(args.name, args.role)
        return
    
    elif args.command == "transfer":
        from session.manager import SessionManager
        
        if args.mode == "server":
            mgr = SessionManager("server", args.key_path,args.output)
            await mgr.establish_channel()  # Waits for client + handshake
            print("✅ Server handshake complete. Waiting for file...")
            await mgr.recv_file(args.output)  # NOW safe to call
            await mgr.close()
            print(f"✅ SERVER: Received {args.output}")
            
        elif args.mode == "client":
            host_port = args.host.split(":")
            mgr = SessionManager("client", args.key_path)
            await mgr.establish_channel()
            await mgr.send_file(args.file)
            await mgr.close()
            print(f"✅ CLIENT: Sent {args.file}")
    else:
        parser.print_help()
        sys.exit(1)
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
