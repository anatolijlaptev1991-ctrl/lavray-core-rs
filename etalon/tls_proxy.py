#!/usr/bin/env python3
"""TCP-прокси для отладки TLS 1.3: клиент → 4433-прокси → s_server(4434).
Логирует направления, размеры, FIN/EOF. Байты не расшифровываются."""

import socket
import threading
import sys

LISTEN = 4433
TARGET = ("127.0.0.1", 4434)

def pump(src: socket.socket, dst: socket.socket, tag: str):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                print(f"[{tag}] EOF ({len(data)})")
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return
            print(f"[{tag}] {len(data)} bytes: {data[:8].hex()}...")
            dst.sendall(data)
    except OSError as e:
        print(f"[{tag}] err: {e}")

def main():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", LISTEN))
    srv.listen(1)
    print(f"proxy listening {LISTEN} -> {TARGET}")
    client, addr = srv.accept()
    print("client connected")
    server = socket.socket()
    server.connect(TARGET)
    print("connected to target")
    t1 = threading.Thread(target=pump, args=(client, server, "C>S"), daemon=True)
    t2 = threading.Thread(target=pump, args=(server, client, "S>C"), daemon=True)
    t1.start()
    t2.start()
    t1.join(30)
    print("done")

if __name__ == "__main__":
    main()
