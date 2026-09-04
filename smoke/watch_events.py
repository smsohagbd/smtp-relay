"""Prints the first few frames from the relay's SSE endpoint."""

import socket
import sys

PORT = int(sys.argv[1])
WANTED = int(sys.argv[2]) if len(sys.argv) > 2 else 6

sock = socket.create_connection(("127.0.0.1", PORT), timeout=20)
sock.sendall(
    b"GET /api/events HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\n\r\n"
)

seen = 0
buffer = b""
while seen < WANTED:
    chunk = sock.recv(4096)
    if not chunk:
        break
    buffer += chunk
    while b"\n" in buffer:
        line, buffer = buffer.split(b"\n", 1)
        text = line.decode(errors="replace").rstrip()
        if text.startswith("event:") or text.startswith("data:"):
            print(text[:180])
            if text.startswith("data:"):
                seen += 1
sock.close()
