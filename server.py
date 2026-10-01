import socket
import threading
import subprocess
import base64
import os

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

HOST = "0.0.0.0"
PORT = 5050
BUF = 1048567 # Buffer is used to for TCP byte stream

server_key = RSA.generate(2048) # Generated public and private keys for the server

def encrypt_data(algorithm, key, data):
    if algorithm == "AES":
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(pad(data, 16))
    elif algorithm == "Caesar":
        shift = key[0]
        return bytes([(b + shift) % 256 for b in data])
    return data


def decrypt_data(algorithm, key, data):
    if algorithm == "AES":
        iv = data[:16]
        ct = data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), 16)
    elif algorithm == "Caesar":
        shift = key[0]
        return bytes([(b - shift) % 256 for b in data])
    return data


def handle_client(conn, addr):
    print("New connection:", addr)
    current_dir = os.getcwd()
    secure = False
    algorithm = None
    session_key = None
    try:
        msg = conn.recv(BUF).decode()
        parts = msg.split(",")   # ["SS", "RFMP", "v1.0", "0 or 1"]
        secure = (parts[3] == "1")
        if secure:
            pub_key_bytes = server_key.publickey().export_key(format="DER")
            conn.sendall(("CC," + base64.b64encode(pub_key_bytes).decode()).encode())

            msg = conn.recv(BUF).decode()
            parts = msg.split(",", 3)      # ["EC", algo, enc_key_b64, "user:pubkey"]
            algorithm = parts[1]
            encrypted_session_key = base64.b64decode(parts[2])
            session_key = PKCS1_OAEP.new(server_key).decrypt(encrypted_session_key)
            print("Secure session:", algorithm)
        else:
            conn.sendall(b"CC")

        while True:
            msg = conn.recv(BUF).decode()
            parts = msg.split(",", 2)
            packet_type = parts[0]

            if packet_type == "EN":          # ---- CLOSING PHASE ----
                break

            if packet_type != "CM":
                conn.sendall(b"EE,1,Unknown packet")
                continue

            command_type = parts[1]
            argument = parts[2] if len(parts) > 2 else ""
            if command_type == "prompt":
                if argument.startswith("cd "):
                    new_dir = os.path.join(current_dir, argument[3:].strip())
                    if os.path.isdir(new_dir):
                        current_dir = os.path.normpath(new_dir)
                        conn.sendall(("SC,Now in " + current_dir).encode())
                    else:
                        conn.sendall(b"EE,2,Folder not found")
                else:
                    result = subprocess.run(argument, shell=True, cwd=current_dir,
                                             capture_output=True, text=True)
                    if result.returncode == 0:
                        output = result.stdout.strip().replace("\n", " ") or "Done"
                        conn.sendall(("SC," + output).encode())
                    else:
                        error = result.stderr.strip().replace("\n", " ") or "Command failed"
                        conn.sendall(("EE,3," + error).encode())
            elif command_type == "openRead":
                path = os.path.join(current_dir, argument)
                if not os.path.isfile(path):
                    conn.sendall(("EE,2,File not found: " + argument).encode())
                else:
                    with open(path, "rb") as f:
                        data = f.read()
                    if secure:
                        data = encrypt_data(algorithm, session_key, data)
                    conn.sendall(("DP," + base64.b64encode(data).decode()).encode())
            elif command_type == "openWrite":
                path = os.path.join(current_dir, argument)
                conn.sendall(b"SC,Ready, send the data now")
                msg = conn.recv(BUF).decode()
                parts = msg.split(",", 1)
                raw = base64.b64decode(parts[1])
                if secure:
                    raw = decrypt_data(algorithm, session_key, raw)
                with open(path, "wb") as f:
                    f.write(raw)
                conn.sendall(b"SC,File saved")
            else:
                conn.sendall(("EE,1,Unknown command: " + command_type).encode())
    except Exception as e:
        print("Error with", addr, ":", e)
    finally:
        conn.close()
        print("Closed:", addr)




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