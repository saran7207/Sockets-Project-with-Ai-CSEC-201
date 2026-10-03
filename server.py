import socket
import threading
import subprocess
import base64
import os

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

HOST = "0.0.0.0"   # listen on every network interface this machine has not just localhost
PORT = 5050
BUF = 1048576  # 1 mb per recv() - comfortably bigger than any command or small file we expect

# One RSA key pair for the whole server made once at startup.
# Every client that connects secure talks to this same identity and RSA
# generation is slow enough that doing it per-connection would be wasteful.
server_key = RSA.generate(2048)

def encrypt_data(algorithm, key, data):
    """Scramble data with whichever cipher the client picked during setup.
    Called right before data goes to the network
    """
    if algorithm == "AES":
        iv = get_random_bytes(16)  # fresh random IV every call, so the same
                                    # plaintext never produces the same ciphertext twice
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(pad(data, 16))  # pad: AES needs full 16-byte blocks
                                                     # IV is glued on front so the receiver can use it
    elif algorithm == "Caesar":
        shift = key[0]  # use the first byte of the session key as the shift amount
        return bytes([(b + shift) % 256 for b in data])  # %256 wraps around so every
                                                            # result is still a valid byte
    return data  # algorithm is None which means connection isn't secure. pass through untouched


def decrypt_data(algorithm, key, data):
    """Called right after data arrives off
    the network and before we ever write it to a file"""
    if algorithm == "AES":
        iv = data[:16]   # first 16 bytes are the IV the sender attached
        ct = data[16:]    # everything after that is the real ciphertext
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ct), 16)
    elif algorithm == "Caesar":
        shift = key[0]
        return bytes([(b - shift) % 256 for b in data])  # shift the other way to undo it
    return data


def handle_client(conn, addr):
    """Runs once per connected client, in its own thread.
    This is how the server handles multiple clients at once."""
    print("New connection:", addr)
    current_dir = os.getcwd()   
    secure = False
    algorithm = None
    session_key = None
    try:
        # Start-Packet from the client
        msg = conn.recv(BUF).decode()
        parts = msg.split(",")   
        secure = (parts[3] == "1")

        if secure:
            # Confirm-Connection-Packet - hand over server's PUBLIC key so the client
            # can encrypt data that only the server's private key can open.
            pub_key_bytes = server_key.publickey().export_key(format="DER")
            conn.sendall(("CC," + base64.b64encode(pub_key_bytes).decode()).encode())

            # Encryption-Packet from the client - algorithm choice + RSA-encrypted session key
            msg = conn.recv(BUF).decode()
            parts = msg.split(",", 3)     
            algorithm = parts[1]
            encrypted_session_key = base64.b64decode(parts[2])
            # private key can reverse what was locked with public key.
            # After this line, session_key is the real shared secret both sides use.
            session_key = PKCS1_OAEP.new(server_key).decrypt(encrypted_session_key)
            print("Secure session:", algorithm)
        else:
            # Nothing to exchange - just confirm the connection with a bare CC.
            conn.sendall(b"CC")

        # Keep handling one packet after another until the client says EN.
        while True:
            msg = conn.recv(BUF).decode()
            parts = msg.split(",", 2)
            packet_type = parts[0]

            if packet_type == "EN":          # Closing phase
                break                         # client said goodbye. stop looping

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
                    # Every other prompt command (mkdir, del, ren, dir, ...) is
                    # just handed to the real OS shell. cwd=current_dir is what
                    # makes it run "as if" we were sitting inside that folder.
                    result = subprocess.run(argument, shell=True, cwd=current_dir,
                                             capture_output=True, text=True)
                    if result.returncode == 0:   # 0 successful execution
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
                    with open(path, "rb") as f:   # rb is used so that raw bytes can be read
                        data = f.read()            

                    # Encrypt in transit only. The file on disk is never
                    # touched - this data variable is just the copy we are
                    # about to send over the socket.
                    if secure:
                        data = encrypt_data(algorithm, session_key, data)

                    conn.sendall(("DP," + base64.b64encode(data).decode()).encode())

            elif command_type == "openWrite":
                path = os.path.join(current_dir, argument)
                # Tell the client go ahead, send the file now - the client
                # is written to wait for this exact reply before sending its
                # DP packet, which is what keeps both sides in step.
                conn.sendall(b"SC,Ready, send the data now")

                msg = conn.recv(BUF).decode()
                parts = msg.split(",", 1)
                raw = base64.b64decode(parts[1])

                # The file that ends up on disk is always plain, readable bytes
                # encryption only ever protected it while in transit.
                if secure:
                    raw = decrypt_data(algorithm, session_key, raw)

                with open(path, "wb") as f:   # wb means write raw bytes
                    f.write(raw)
                conn.sendall(b"SC,File saved")

            else:
                conn.sendall(("EE,1,Unknown command: " + command_type).encode())
    except Exception as e:
        # Catches anything unexpected, client disconnecting mid-conversation,
        # a malformed packet, etc. so one bad client can't crash the whole
        # server - only its own thread ends.
        print("Error with", addr, ":", e)
    finally:
        # Runs no matter what - normal EN, or an exception above so we
        # never leak an open connection.
        conn.close()
        print("Closed:", addr)


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # AF_INET = IPv4, SOCK_STREAM = TCP
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(5) 
    print(f"Server listening on port {PORT}")

    # This loop is the only thing the main thread ever does wait for a
    # client, hand it off to its own thread, go back to waiting.
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
        # daemon=True - these background threads won't stop Ctrl+C from
        # actually exiting the program, even if a client is still connected.


if __name__ == "__main__":
    main()