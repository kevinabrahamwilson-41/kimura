# file_transfer/transfer.py
"""
secure file transfer over asyncio TCP.
"""

import asyncio
import struct
import os
import sys
from pathlib import Path

# Fix imports for project structure
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.dirname(__file__))  # file_transfer/
from crypto.aead import AEADContext
from file_transfer.chunking import chunk_file_for_encryption, ChunkMetadata, verify_chunk_integrity
from file_transfer.bytes_conversion import format_file_size, get_file_size


async def send_length_prefixed(writer: asyncio.StreamWriter, data: bytes) -> None:
    """Send data with 4-byte length prefix."""
    length = len(data)
    writer.write(struct.pack('>I', length))  # 4-byte length
    writer.write(data)
    await writer.drain()


async def recv_length_prefixed(reader: asyncio.StreamReader) -> bytes:
    """Receive exact data from length prefix."""
    length_data = await reader.readexactly(4)
    length = struct.unpack('>I', length_data)[0]
    
    data = bytearray()
    while len(data) < length:
        chunk = await reader.read(length - len(data))
        if not chunk:
            raise asyncio.IncompleteReadError(f"Expected {length}, got {len(data)}")
        data.extend(chunk)
    return bytes(data)


async def send_file(
    writer: asyncio.StreamWriter,
    filepath: Path,
    aead_ctx: AEADContext,
    chunk_size: int = 64 * 1024,
) -> None:
    """✅ USES chunk_file_for_encryption() - Send encrypted chunks."""
    file_size = get_file_size(filepath)
    total_chunks = (file_size + chunk_size - 1) // chunk_size
    
    # 1. Send file header: total_chunks, file_size
    header = struct.pack('>QQ', total_chunks, file_size)
    await send_length_prefixed(writer, header)
    
    # 2. ✅ USE chunk_file_for_encryption() - Production chunking!
    chunks_sent = 0
    for metadata, chunk in chunk_file_for_encryption(filepath, chunk_size):
        # Encrypt with unique nonce
        nonce = aead_ctx.generate_nonce()
        encrypted = aead_ctx.encrypt(chunk, nonce)
        
        # Packet: index(8) + size(8) + hash(32) + nonce(12) + encrypted
        msg = (metadata.index.to_bytes(8, 'big') +           # 0-8
               metadata.size.to_bytes(8, 'big') +           # 8-16  
               metadata.hash +                              # 16-48 (SHA256)
               nonce +                                      # 48-60
               encrypted)                                  # 60-end
        
        await send_length_prefixed(writer, msg)
        chunks_sent += 1
        
        print(f"\rSending chunk {chunks_sent}/{total_chunks}", end='')
    
    print(f"\n✅ Sent {chunks_sent} chunks ({format_file_size(file_size)})")


async def recv_file(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    output_path: Path,
    aead_ctx: AEADContext,
) -> Path:
    """✅ FULL integrity verification with ChunkMetadata."""
    # 1. Read header
    header = await recv_length_prefixed(reader)
    total_chunks, expected_size = struct.unpack('>QQ', header)
    
    chunks = []
    for i in range(total_chunks):
        # 2. Read encrypted chunk packet
        msg = await recv_length_prefixed(reader)
        
        # Parse packet format
        index = int.from_bytes(msg[:8], 'big')
        size = int.from_bytes(msg[8:16], 'big')
        chunk_hash = msg[16:48]                           # SHA256 hash
        nonce = msg[48:60]                                # 12-byte nonce
        encrypted = msg[60:]                              # Encrypted data
        
        # 3. Decrypt
        chunk = aead_ctx.decrypt(encrypted, nonce)
        
        # 4. ✅ USE verify_chunk_integrity() - Production verification!
        metadata = ChunkMetadata(index, size, chunk_hash)
        if not verify_chunk_integrity(metadata, chunk):
            raise ValueError(f"❌ Integrity fail at chunk {index}")
        
        chunks.append((index, chunk))
        print(f"\rReceiving chunk {i+1}/{total_chunks}", end='')
    
    # 5. Reassemble in order
    chunks.sort(key=lambda x: x[0])
    output_path.parent.mkdir(exist_ok=True)
    with open(output_path, 'wb') as f:
        for _, chunk in chunks:
            f.write(chunk)
    
    print(f"\n✅ Received {format_file_size(expected_size)} - Verified!")
    return output_path


# High-level server/client
async def file_server(host: str, port: int, output_dir: Path, key: bytes):
    """TCP server - receive files."""
    aead_ctx = AEADContext(key)
    output_dir.mkdir(exist_ok=True)
    
    async def handle_client(reader, writer):
        try:
            await recv_file(reader, writer, output_dir / "received.bin", aead_ctx)
        except Exception as e:
            print(f"❌ Client error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
    
    server = await asyncio.start_server(handle_client, host, port)
    async with server:
        print(f"🚀 PQC File Server listening on {host}:{port}")
        await server.serve_forever()


async def file_client(host: str, port: int, filepath: Path, key: bytes):
    """TCP client - send files."""
    aead_ctx = AEADContext(key)
    reader, writer = await asyncio.open_connection(host, port)
    try:
        await send_file(writer, filepath, aead_ctx)
    except Exception as e:
        print(f"❌ Send failed: {e}")
    finally:
        writer.close()
        await writer.wait_closed()


# CLI Interface
async def main():
    import sys
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python -m file_transfer.transfer --server 0.0.0.0:12345")
        print("  python -m file_transfer.transfer --client 127.0.0.1:12345 model.pt")
        return
    
    # Production: derive from PQC handshake!
    key = os.urandom(32)
    
    if sys.argv[1] == "--server":
        host, port = sys.argv[2].split(':')
        await file_server(host, int(port), Path("downloads"), key)
    elif sys.argv[1] == "--client":
        parts = sys.argv[2].split(':')
        host, port = parts[0], int(parts[1])
        filepath = Path(sys.argv[3])
        await file_client(host, port, filepath, key)


if __name__ == "__main__":
    asyncio.run(main())
