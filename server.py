import socket

HOST = "0.0.0.0"
PORT = 5050

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((HOST, PORT))
        server_sock.listen(5)
        print(f"[SERVER] Listening on {HOST}:{PORT}")
        conn, addr = server_sock.accept()
        print(f"[+] Connected: {addr}")
        conn.close()

if __name__ == "__main__":
    main()