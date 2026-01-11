#!/usr/bin/env python3
import asyncio
import argparse
import sys
from pathlib import Path
from session.manager import SessionManager
# Import all keygen functions
from crypto.keygen import (
    generate_mlkem_server_keys, generate_mlkem_client_keys,
    generate_mldsa_server_keys, generate_mldsa_client_keys
)
from protocol.state_machine import StateMachine
async def main():
    parser = argparse.ArgumentParser("pqc-session", description="PQC Secure File Transfer")
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # 🔥 1. ML-KEM KEYGEN COMMANDS
    kem_parser = subparsers.add_parser("mlkem-server", help="Generate server ML-KEM keys")
    kem_parser.add_argument("--key-path", default="./keys", help="Path to keys/")
    
    kemc_parser = subparsers.add_parser("mlkem-client", help="Generate client ML-KEM keys")
    kemc_parser.add_argument("--key-path", default="./keys", help="Path to keys/")
    
    # 🔥 2. ML-DSA KEYGEN COMMANDS  
    dsas_parser = subparsers.add_parser("mldsa-server", help="Generate server ML-DSA keys")
    dsas_parser.add_argument("--key-path", default="./keys", help="Path to keys/")
    
    dsac_parser = subparsers.add_parser("mldsa-client", help="Generate client ML-DSA keys")
    dsac_parser.add_argument("--key-path", default="./keys", help="Path to keys/")
    
    # 🔥 3. TRANSFER COMMANDS (unchanged)
    transfer_parser = subparsers.add_parser("transfer", help="PQC file transfer")
    transfer_subparsers = transfer_parser.add_subparsers(dest="mode", help="Transfer mode")
    
    # SERVER MODE
    server_parser = transfer_subparsers.add_parser("server", help="Receive file")
    server_parser.add_argument("--port", type=int, default=8443)
    server_parser.add_argument("--output", required=True, help="Output file path")
    server_parser.add_argument("--key-path", default="./keys", help="Path to keys/")
    server_parser.add_argument("--persistent", action="store_true", 
                          help="Keep server alive for multiple GPU clients")
    # CLIENT MODE  
    client_parser = transfer_subparsers.add_parser("client", help="Send file")
    client_parser.add_argument("host", help="server:port (ex: 127.0.0.1:8443)")
    client_parser.add_argument("--file", required=True, help="File to send")
    client_parser.add_argument("--key-path", default="./keys", help="Path to keys/")
    
    args = parser.parse_args()
    
    # REPLACE keygen calls with ABSOLUTE PATHS:
    if args.command == "mlkem-server":
        generate_mlkem_server_keys(args.key_path)
        return
    elif args.command == "mlkem-client":
        generate_mlkem_client_keys(args.key_path)
        return
    elif args.command == "mldsa-server":
        generate_mldsa_server_keys(args.key_path)
        return
    elif args.command == "mldsa-client":
        generate_mldsa_client_keys(args.key_path)
        return


    elif args.command == "transfer":
        if args.mode == "server":
            if args.persistent:
                print("🚀 SEQUENTIAL GPU SERVER - Unlimited clients one-by-one!")
                client_count = 0
                
                while True:
                    print(f"\n🎯 Waiting for GPU Client #{client_count + 1}...")
                    output_file = f"{Path(args.output).stem}_gpu{client_count}.bin"
                    mgr = SessionManager("server", args.key_path, str(output_file))
                    
                    try:
                        await mgr.establish_channel()  # Works perfectly
                        print(f"✅ GPU Client #{client_count}: PQC handshake complete!")
                        await mgr.recv_file(str(output_file))
                        print(f"✅ GPU Client #{client_count}: '{output_file}' saved!")
                    except Exception as e:
                        print(f"❌ GPU Client #{client_count} error: {e}")
                    finally:
                        await mgr.close()
                    
                    client_count += 1
                    print(f"🚀 Server ready for next GPU client...\n")

            else:
                # Single transfer (unchanged)
                mgr = SessionManager("server", str(Path(args.key_path).resolve()), str(args.output))
                await mgr.establish_channel()
                await mgr.recv_file(args.output)
                await mgr.close()
                print(f"✅ SERVER: Verified {args.output} received!")

        elif args.mode == "client":
            host_port = args.host.split(":")
            mgr = SessionManager("client", str(Path(args.key_path).resolve()), args.file)
            
            # FIX: Pass host/port to constructor or separate connect method
            mgr.host = host_port[0]   # Add these 2 lines
            mgr.port = int(host_port[1])
            
            await mgr.establish_channel()  # Now works - no extra args!
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
