#!/usr/bin/env python3
import asyncio
import logging
from kimura.protocol.state_machine import StateMachine
from protocol.constants import DEFAULT_PORT  


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-5s %(message)s"
)
log = logging.getLogger("pqc_server")


async def handle_one(reader, writer):
    """
    Per‑client handler that runs a full PQC handshake.
    """
    log.info("New connection accepted from %s", writer.get_extra_info("peername"))

    sm = StateMachine("keys", "server")

    try:
        # LOG: entering the first handshake step
        log.info("CLIENT -> SERVER: starting recv_handshake")
        await sm.transition("recv_handshake", reader=reader, writer=writer)

        log.info("CLIENT <- SERVER: sending response")
        await sm.transition("send_response", reader=reader, writer=writer)

        log.info("HANDSHAKE completed for this client")
    except Exception as e:
        log.error("HANDSHAKE failed: %s", e, exc_info=True)
    finally:
        writer.close()
        await writer.wait_closed()


async def main():
    """
    Start the TCP server that listens on 127.0.0.1:8000 for PQC‑handshakes.
    """
    try:
        server = await asyncio.start_server(
            handle_one,
            "127.0.0.1",
            DEFAULT_PORT,
        )

        # DEBUG: show exactly what we're bound to
        sock = server.sockets[0]
        sockname = sock.getsockname()
        log.info("Server bound to %s:%s", sockname[0], sockname[1])

        log.info(f"PQC‑ENCRYPTED SERVER listening on 127.0.0.1:{DEFAULT_PORT}...")
        async with server:
            await server.serve_forever()

    except Exception as e:
        log.error("SERVER failed to start: %s", e, exc_info=True)
        raise


if __name__ == "__main__":
    asyncio.run(main())
