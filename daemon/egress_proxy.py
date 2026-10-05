"""
daemon/egress_proxy.py - Local egress filtering proxy for Leash L2 containment (M6.5).

Filters outbound HTTP and HTTPS (CONNECT) traffic from agent containers or environments.
Only hosts permitted in session scope (e.g., package registry, git remote) are allowed.
Blocked requests return HTTP 403 and are logged to audit/monitoring.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Callable, List, Optional, Set, Tuple

logger = logging.getLogger("leash.daemon.egress_proxy")


class EgressProxy:
    """Async HTTP / HTTPS CONNECT egress proxy that enforces host allowlists."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 0,
        allowed_hosts: Optional[Set[str]] = None,
        is_host_allowed_fn: Optional[Callable[[str], bool]] = None,
    ):
        self.host = host
        self.port = port
        self.allowed_hosts = {h.lower() for h in (allowed_hosts or set())}
        self.is_host_allowed_fn = is_host_allowed_fn
        self.blocked_hosts: List[Tuple[str, float]] = []
        self._server: Optional[asyncio.Server] = None
        self._running = False

    def is_allowed(self, target_host: str) -> bool:
        clean = target_host.lower().strip()
        if ":" in clean:
            clean = clean.split(":")[0]

        if self.is_host_allowed_fn:
            return self.is_host_allowed_fn(clean)

        if not self.allowed_hosts:
            return False

        if "*" in self.allowed_hosts or clean in self.allowed_hosts:
            return True

        # Wildcard domain match (e.g. *.github.com)
        for allowed in self.allowed_hosts:
            if allowed.startswith("*."):
                suffix = allowed[1:]  # .github.com
                if clean.endswith(suffix):
                    return True
        return False

    async def start(self) -> int:
        """Starts the proxy server and returns the bound port."""
        self._server = await asyncio.start_server(self._handle_client, self.host, self.port)
        self.port = self._server.sockets[0].getsockname()[1]
        self._running = True
        logger.info(f"Egress proxy started on {self.host}:{self.port}")
        return self.port

    async def stop(self) -> None:
        """Stops the proxy server."""
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        logger.info("Egress proxy stopped")

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            line = await reader.readline()
            if not line:
                writer.close()
                await writer.wait_closed()
                return

            req_line = line.decode("latin1", errors="replace").strip()
            parts = req_line.split()
            if len(parts) < 2:
                writer.close()
                await writer.wait_closed()
                return

            method, target = parts[0].upper(), parts[1]

            # Read headers until empty line
            headers = []
            host_header = ""
            while True:
                h_line = await reader.readline()
                if not h_line or h_line == b"\r\n" or h_line == b"\n":
                    break
                decoded_h = h_line.decode("latin1", errors="replace").strip()
                headers.append(decoded_h)
                if decoded_h.lower().startswith("host:"):
                    host_header = decoded_h[5:].strip()

            target_host = ""
            target_port = 80
            if method == "CONNECT":
                # HTTPS Tunnel: CONNECT host:port HTTP/1.1
                if ":" in target:
                    h, p = target.split(":", 1)
                    target_host = h
                    try:
                        target_port = int(p)
                    except ValueError:
                        target_port = 443
                else:
                    target_host = target
                    target_port = 443
            else:
                # HTTP: GET http://host:port/path or GET /path with Host: header
                if target.startswith("http://") or target.startswith("https://"):
                    no_scheme = target.split("://", 1)[1]
                    target_host = no_scheme.split("/", 1)[0]
                elif host_header:
                    target_host = host_header

                if ":" in target_host:
                    h, p = target_host.split(":", 1)
                    target_host = h
                    try:
                        target_port = int(p)
                    except ValueError:
                        target_port = 80

            # Host verification check
            loop = asyncio.get_event_loop()
            if not self.is_allowed(target_host):
                self.blocked_hosts.append((target_host, loop.time()))
                logger.warning(f"Egress proxy blocked destination: {target_host}:{target_port}")
                body = f"403 Forbidden - Leash Egress Control blocked host: {target_host}\r\n".encode("utf-8")
                writer.write(
                    b"HTTP/1.1 403 Forbidden\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
                    b"Connection: close\r\n\r\n" + body
                )
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            # Permitted destination: proxy connection
            try:
                remote_reader, remote_writer = await asyncio.open_connection(target_host, target_port)
            except Exception as e:
                logger.debug(f"Failed to connect to {target_host}:{target_port}: {e}")
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            if method == "CONNECT":
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await writer.drain()
            else:
                # Forward request line and headers
                remote_writer.write(line)
                for h in headers:
                    remote_writer.write(f"{h}\r\n".encode("latin1"))
                remote_writer.write(b"\r\n")
                await remote_writer.drain()

            # Bidirectional pipe
            async def forward(src: asyncio.StreamReader, dst: asyncio.StreamWriter):
                try:
                    while True:
                        buf = await src.read(8192)
                        if not buf:
                            break
                        dst.write(buf)
                        await dst.drain()
                except Exception:
                    pass
                finally:
                    try:
                        dst.close()
                        await dst.wait_closed()
                    except Exception:
                        pass

            await asyncio.gather(
                forward(reader, remote_writer),
                forward(remote_reader, writer),
                return_exceptions=True,
            )

        except Exception as e:
            logger.debug(f"Error handling proxy client: {e}")
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
