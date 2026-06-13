#!/usr/bin/env python3
import socket
import time

TARGET_IP = "192.168.20.10"
TARGET_PORT = 80
PATH = "/mfolder/"

# Body da inviare (31 byte come nel tuo esempio)
body = "username=admin&password=test123"

# Dividi in 3 chunk di dimensioni (11, 10, 10)
chunks = [
    body[:11],   # "username=ad"
    body[11:21], # "min&passwo"
    body[21:]    # "rd=test123"
]

# Costruzione della richiesta (senza Content-Length, con Transfer-Encoding: chunked)
request_headers = (
    f"POST {PATH} HTTP/1.1\r\n"
    f"Host: {TARGET_IP}\r\n"
    f"User-Agent: test-chunked\r\n"
    f"Accept: */*\r\n"
    f"Content-Type: application/x-www-form-urlencoded\r\n"
    f"Transfer-Encoding: chunked\r\n"
    f"Connection: close\r\n"
    "\r\n"
)

# Connessione
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TARGET_IP, TARGET_PORT))

# Invia headers
s.send(request_headers.encode())

# Invia ogni chunk con ritardo per vedere separazione in Wireshark
for i, chunk in enumerate(chunks):
    chunk_size_hex = f"{len(chunk):x}"
    s.send(f"{chunk_size_hex}\r\n".encode())
    s.send(chunk.encode())
    s.send(b"\r\n")
    print(f"Chunk {i+1}: {len(chunk)} bytes -> '{chunk}'")
    time.sleep(0.5)  # ritardo di 500 ms tra un chunk e l'altro

# Chunk finale
s.send(b"0\r\n\r\n")
print("Chunk finale 0 inviato")

# Ricevi risposta
response = s.recv(4096)
print("Risposta ricevuta:\n", response.decode(errors='ignore'))
s.close()