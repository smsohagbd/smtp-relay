"""Submits a Mautic-shaped message to the relay and prints every reply."""

import socket
import sys

PORT = int(sys.argv[1])

MESSAGE = (
    b"From: Acme Marketing <campaigns@acme-mautic.io>\r\n"
    b"To: Lead One <lead@example.org>\r\n"
    b"Cc: watcher@example.org\r\n"
    b"Subject: =?UTF-8?Q?Your_September_Offer?=\r\n"
    b"MIME-Version: 1.0\r\n"
    b"List-Unsubscribe: <https://acme-mautic.io/unsubscribe/xyz>\r\n"
    b"DKIM-Signature: v=1; a=rsa-sha256; d=acme-mautic.io; h=from:to;\r\n"
    b" b=SIGNATUREDATA/1234+abc==\r\n"
    b'Content-Type: multipart/alternative; boundary="__part__"\r\n'
    b"\r\n"
    b"--__part__\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"Content-Transfer-Encoding: quoted-printable\r\n"
    b"\r\n"
    b"Hello =E2=80=94 see https://acme-mautic.io/r/abc123 for details.\r\n"
    b".leading dot line must survive\r\n"
    b"--__part__\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n"
    b"\r\n"
    b'<html><body><a href="https://acme-mautic.io/r/abc123">Click</a>'
    b'<img src="https://acme-mautic.io/email/abc123.gif" /></body></html>\r\n'
    b"--__part__--\r\n"
)

sock = socket.create_connection(("127.0.0.1", PORT), timeout=20)
sock_file = sock.makefile("rb")


def expect(prefix, label):
    line = sock_file.readline()
    while line[3:4] == b"-":
        line = sock_file.readline()
    text = line.decode(errors="replace").rstrip()
    print(f"{label}: {text}")
    if not text.startswith(prefix):
        raise SystemExit(f"FAIL {label}: expected {prefix}, got {text}")


def send(command, prefix, label):
    sock.sendall(command)
    expect(prefix, label)


expect("220", "banner")
send(b"EHLO mautic.local\r\n", "250", "ehlo")
send(b"MAIL FROM:<campaigns@acme-mautic.io>\r\n", "250", "mail from")
send(b"RCPT TO:<lead@example.org>\r\n", "250", "rcpt to")
send(b"RCPT TO:<watcher@example.org>\r\n", "250", "rcpt cc")
send(b"DATA\r\n", "354", "data")
send(MESSAGE + b".\r\n", "250", "message")
send(b"QUIT\r\n", "221", "quit")
print("submission OK")
