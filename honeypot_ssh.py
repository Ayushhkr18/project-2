import os
import socket
import sys
import threading
import traceback
import paramiko
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from generator import GenerativeContentEngine
from world_builder import VirtualFilesystemBuilder
from interaction_engine import StatefulInteractionEngine

# Event handlers to push live feeds to app.py
ON_SESSION_START = None
ON_SESSION_EVENT = None
ON_SESSION_END = None

class DecoySSHServer(paramiko.ServerInterface):
    def __init__(self, client_addr, session_id, log_callback):
        self.event = threading.Event()
        self.client_addr = client_addr
        self.session_id = session_id
        self.log_callback = log_callback
        self.username = None

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.username = username
        # Log auth attempt details
        self.log_callback({
            "type": "auth_attempt",
            "username": username,
            "password": password,
            "status": "success"  # Accept all credentials to lure attackers in!
        })
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        self.username = username
        self.log_callback({
            "type": "auth_attempt",
            "username": username,
            "key_fingerprint": key.get_fingerprint().hex(),
            "status": "success"
        })
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return 'password,publickey'

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True


def handle_client(client_socket, client_addr, host_key, engine_factory):
    session_id = str(threading.get_native_id())
    session_logs = []

    def log_event(event):
        event["session_id"] = session_id
        event["ip"] = client_addr[0]
        event["port"] = client_addr[1]
        session_logs.append(event)
        if ON_SESSION_EVENT:
            ON_SESSION_EVENT(session_id, event)

    try:
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(host_key)
        
        server = DecoySSHServer(client_addr, session_id, log_event)
        try:
            transport.start_server(server=server)
        except paramiko.SSHException:
            return

        # Wait for authentication
        chan = transport.accept(20)
        if chan is None:
            return

        # Wait for shell request
        server.event.wait(10)
        if not server.event.is_set():
            chan.close()
            return

        # Session accepted! Trigger start callback
        if ON_SESSION_START:
            ON_SESSION_START(session_id, client_addr[0], server.username or "unknown")

        # Initialize filesystem builder and interaction engine for this unique attacker session
        gen_engine = GenerativeContentEngine()
        fs_builder = VirtualFilesystemBuilder(gen_engine)
        interaction_engine = StatefulInteractionEngine(fs_builder)

        # Welcome banner
        welcome = f"Welcome to staging-node-03 ({gen_engine.tech_stack})\nLast login: Tue Aug 18 10:24:18 2026 from 192.168.1.45\r\n"
        chan.send(welcome)

        # Interactive shell loop
        buffer = ""
        prompt = f"{server.username or 'admin'}@staging-node-03:{interaction_engine.cwd.replace('/home/admin', '~')}# "
        chan.send(prompt)

        while True:
            # Read input characters
            try:
                char = chan.recv(1).decode("utf-8", errors="ignore")
            except Exception:
                break
            
            if not char:
                break

            # Handle character typing echo
            if char in ["\r", "\n"]:
                chan.send("\r\n")
                cmd_line = buffer.strip()
                buffer = ""
                
                if cmd_line == "exit":
                    break
                
                if cmd_line:
                    # Execute command in the interaction engine
                    output, mitre = interaction_engine.execute_command(cmd_line)
                    
                    # Log the command and response details
                    log_event({
                        "type": "command",
                        "command": cmd_line,
                        "output": output,
                        "mitre": mitre
                    })
                    
                    # Format output line endings for raw SSH channel
                    formatted_output = output.replace("\n", "\r\n")
                    chan.send(formatted_output)
                
                # Send next prompt
                prompt = f"{server.username or 'admin'}@staging-node-03:{interaction_engine.cwd.replace('/home/admin', '~')}# "
                chan.send(prompt)
                
            elif char in ["\x7f", "\x08"]:  # Backspace handling
                if len(buffer) > 0:
                    buffer = buffer[:-1]
                    chan.send("\b \b")  # Send erase sequence
            elif char == "\x03":  # Ctrl+C
                chan.send("^C\r\n")
                buffer = ""
                prompt = f"{server.username or 'admin'}@staging-node-03:{interaction_engine.cwd.replace('/home/admin', '~')}# "
                chan.send(prompt)
            else:
                buffer += char
                chan.send(char)  # Echo back character

    except Exception as e:
        traceback.print_exc()
    finally:
        try:
            chan.close()
        except Exception:
            pass
        transport.close()
        if ON_SESSION_END:
            ON_SESSION_END(session_id)


def generate_transient_host_key():
    """
    Generates a transient RSA host key to use for the SSH listener.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    # Write key to a temporary local file or load directly
    return paramiko.RSAKey(file_obj=sys.io.StringIO(private_key_pem.decode('utf-8'))) if hasattr(sys, 'io') else paramiko.RSAKey.from_private_key(io.StringIO(private_key_pem.decode('utf-8')))

# Fallback method to load/save RSA key safely
import io
def load_or_create_host_key(filepath="host.key"):
    if os.path.exists(filepath):
        return paramiko.RSAKey(filename=filepath)
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        with open(filepath, "w") as f:
            f.write(private_pem)
        return paramiko.RSAKey(filename=filepath)


def start_ssh_honeypot(port=2222, host="0.0.0.0"):
    host_key = load_or_create_host_key()
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((host, port))
        server_socket.listen(10)
        print(f"[*] Decoy SSH Honeypot Server listening on {host}:{port}...")
    except Exception as e:
        print(f"[-] Failed to bind socket to port {port}: {e}")
        return

    def listen_loop():
        while True:
            try:
                client_socket, client_addr = server_socket.accept()
                t = threading.Thread(target=handle_client, args=(client_socket, client_addr, host_key, None))
                t.daemon = True
                t.start()
            except Exception:
                break
                
    threading.Thread(target=listen_loop, daemon=True).start()
    return server_socket
