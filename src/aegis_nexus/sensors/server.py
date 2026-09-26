from __future__ import annotations

import socket
import socketserver
import threading


class BoundedThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 64

    def __init__(self, server_address, handler_class, max_connections: int = 32):
        self._slots = threading.BoundedSemaphore(max(1, min(max_connections, 256)))
        host = str(server_address[0])
        self.address_family = socket.AF_INET6 if ":" in host else socket.AF_INET
        super().__init__(server_address, handler_class)

    def server_bind(self):
        if self.address_family == socket.AF_INET6 and str(self.server_address[0]) == "::":
            try:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except OSError:
                pass
        super().server_bind()

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()
