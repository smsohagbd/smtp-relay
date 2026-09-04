"""Minimal SMTP sink used by the smoke test.

Speaks just enough ESMTP (with AUTH PLAIN/LOGIN) to accept one message and
write it to disk, so the relay's rewriting can be checked byte for byte.
"""

import socket
import sys
import threading

PORT = int(sys.argv[1])
OUT = sys.argv[2]


def handle(conn):
    conn.sendall(b"220 fake-upstream ESMTP ready\r\n")
    data = b""
    reading_data = False
    buffer = b""

    while True:
        chunk = conn.recv(65536)
        if not chunk:
            break
        buffer += chunk

        while b"\r\n" in buffer:
            line, buffer = buffer.split(b"\r\n", 1)

            if reading_data:
                if line == b".":
                    reading_data = False
                    with open(OUT, "wb") as handle_out:
                        handle_out.write(data)
                    conn.sendall(b"250 2.0.0 Ok: queued as FAKE123\r\n")
                    continue
                data += (line[1:] if line.startswith(b"..") else line) + b"\r\n"
                continue

            upper = line.upper()
            if upper.startswith(b"EHLO"):
                conn.sendall(
                    b"250-fake-upstream\r\n"
                    b"250-SIZE 52428800\r\n"
                    b"250-AUTH PLAIN LOGIN\r\n"
                    b"250 ENHANCEDSTATUSCODES\r\n"
                )
            elif upper.startswith(b"HELO"):
                conn.sendall(b"250 fake-upstream\r\n")
            elif upper.startswith(b"AUTH LOGIN"):
                conn.sendall(b"334 VXNlcm5hbWU6\r\n")
            elif upper.startswith(b"AUTH PLAIN"):
                conn.sendall(b"235 2.7.0 authenticated\r\n")
            elif upper.startswith(b"MAIL FROM"):
                conn.sendall(b"250 2.1.0 sender ok\r\n")
            elif upper.startswith(b"RCPT TO"):
                conn.sendall(b"250 2.1.5 recipient ok\r\n")
            elif upper == b"DATA":
                reading_data = True
                conn.sendall(b"354 end with <CRLF>.<CRLF>\r\n")
            elif upper == b"RSET":
                conn.sendall(b"250 2.0.0 reset\r\n")
            elif upper == b"NOOP":
                conn.sendall(b"250 2.0.0 ok\r\n")
            elif upper == b"QUIT":
                conn.sendall(b"221 2.0.0 bye\r\n")
                conn.close()
                return
            else:
                # Base64 credential lines arrive here during AUTH LOGIN.
                conn.sendall(b"235 2.7.0 authenticated\r\n")


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", PORT))
server.listen(8)
print(f"fake upstream listening on {PORT}", flush=True)

while True:
    connection, _ = server.accept()
    threading.Thread(target=handle, args=(connection,), daemon=True).start()
