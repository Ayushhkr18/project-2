import os
import re
import random
from world_builder import VirtualFilesystemBuilder

class StatefulInteractionEngine:
    def __init__(self, fs_builder: VirtualFilesystemBuilder, use_llm_simulation=True):
        self.fs = fs_builder
        self.use_llm_simulation = use_llm_simulation
        self.cwd = "/home/admin"
        self.env = {
            "USER": "admin",
            "HOME": "/home/admin",
            "SHELL": "/bin/bash",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "PWD": "/home/admin"
        }
        
        # MITRE ATT&CK Mapping rules matching patterns
        self.mitre_patterns = [
            (r"^(whoami|id|groups|w|last)", "Discovery", "T1033", "System Owner/User Discovery"),
            (r"^(uname|hostname|cat /etc/issue|cat /etc/\*release)", "Discovery", "T1082", "System Information Discovery"),
            (r"^(ifconfig|ip addr|route|netstat|arp)", "Discovery", "T1049", "System Network Connections Discovery"),
            (r"^(ps|top|htop)", "Discovery", "T1057", "Process Discovery"),
            (r"^(ls|find|locate|pwd)", "Discovery", "T1083", "File and Directory Discovery"),
            (r"cat\s+.*shadow", "Credential Access", "T1003.008", "Security Account Manager / /etc/shadow Access"),
            (r"cat\s+.*id_rsa", "Credential Access", "T1552.004", "Private Keys Extraction"),
            (r"cat\s+.*credentials", "Credential Access", "T1552.001", "Credentials In Files"),
            (r"cat\s+.*database\.yml", "Credential Access", "T1552.001", "Database Configuration Honeytoken Access"),
            (r"^(curl|wget|fetch)\s+http", "Ingress Tool Transfer", "T1105", "Remote File Copy / Tool Ingress"),
            (r"^(chmod \+x|chmod 755)", "Defense Evasion", "T1222.002", "Linux File and Directory Permissions Modification"),
            (r"^(\./|bash |sh ).*", "Execution", "T1059.004", "Unix Shell Script Execution"),
            (r"^(touch |mkdir |echo .* >|cat <<)", "Persistence", "T1059", "Filesystem Artifact Creation")
        ]

    def resolve_path(self, target_path):
        """
        Translates a relative path input against self.cwd into an absolute virtual path.
        """
        if not target_path:
            return self.cwd
        
        # Trim leading/trailing spaces
        target_path = target_path.strip()
        
        if target_path.startswith("/"):
            absolute = target_path
        else:
            absolute = os.path.join(self.cwd, target_path).replace("\\", "/")
        
        # Clean path segments (. and ..)
        parts = absolute.split("/")
        cleaned = []
        for part in parts:
            if part == "" or part == ".":
                continue
            if part == "..":
                if cleaned:
                    cleaned.pop()
            else:
                cleaned.append(part)
        
        return "/" + "/".join(cleaned)

    def classify_mitre(self, command):
        """
        Scans commands and maps them to MITRE ATT&CK tactics & techniques.
        """
        command = command.strip()
        for pattern, tactic, technique_id, name in self.mitre_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return {
                    "tactic": tactic,
                    "technique_id": technique_id,
                    "name": name,
                    "severity": "high" if "Credential Access" in tactic or "Tool Transfer" in tactic or "Execution" in tactic else "low"
                }
        return {
            "tactic": "Interactive Exploration",
            "technique_id": "T1059",
            "name": "Command and Scripting Interpreter",
            "severity": "info"
        }

    def execute_command(self, full_command):
        """
        Routes the command to either internal deterministic handlers or the simulated generative shell.
        """
        full_command = full_command.strip()
        if not full_command:
            return ""

        # Map command to MITRE ATT&CK
        mitre_mapping = self.classify_mitre(full_command)

        # Basic command parsing
        parts = full_command.split()
        cmd = parts[0]
        args = parts[1:] if len(parts) > 1 else []

        output = ""
        
        # Handlers for deterministic commands
        if cmd == "cd":
            target = args[0] if args else "/home/admin"
            resolved = self.resolve_path(target)
            if self.fs.is_dir(resolved):
                self.cwd = resolved
                self.env["PWD"] = resolved
            else:
                output = f"-bash: cd: {target}: No such file or directory\n"
        elif cmd == "pwd":
            output = f"{self.cwd}\n"
        elif cmd == "clear":
            output = "\033[H\033[2J"  # Clear screen ansi code
        elif cmd == "whoami":
            output = f"{self.env['USER']}\n"
        elif cmd == "id":
            output = "uid=1000(admin) gid=1000(admin) groups=1000(admin),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)\n"
        elif cmd == "exit":
            output = "exit"
        elif cmd == "ls":
            # Simple ls implementation
            target = args[0] if args and not args[0].startswith("-") else "."
            # Filter flags
            show_all = False
            for arg in args:
                if arg.startswith("-") and "a" in arg:
                    show_all = True
            
            resolved = self.resolve_path(target)
            if self.fs.is_dir(resolved):
                entries = self.fs.list_dir(resolved)
                if not show_all:
                    entries = [e for e in entries if not e.startswith(".")]
                # Add default relative dirs
                if show_all:
                    entries = [".", ".."] + entries
                output = "  ".join(entries) + "\n" if entries else ""
            elif self.fs.is_file(resolved):
                output = f"{os.path.basename(resolved)}\n"
            else:
                output = f"ls: cannot access '{target}': No such file or directory\n"
        elif cmd == "cat":
            if not args:
                output = ""
            else:
                target = args[0]
                resolved = self.resolve_path(target)
                if self.fs.is_file(resolved):
                    output = self.fs.read_file_content(resolved)
                elif self.fs.is_dir(resolved):
                    output = f"cat: {target}: Is a directory\n"
                else:
                    output = f"cat: {target}: No such file or directory\n"
        elif cmd == "touch":
            if not args:
                output = "touch: missing file operand\n"
            else:
                target = args[0]
                resolved = self.resolve_path(target)
                self.fs.write_file_content(resolved, "")
                output = ""
        elif cmd == "echo":
            # Simple echo support (e.g. echo hello, or echo content > file)
            # Find redirections
            if ">" in args:
                idx = args.index(">")
                content = " ".join(args[:idx]).strip("'\"")
                target = args[idx+1]
                resolved = self.resolve_path(target)
                self.fs.write_file_content(resolved, content + "\n")
                output = ""
            else:
                output = " ".join(args).strip("'\"") + "\n"
        else:
            # Command falls to our Generative Interaction Layer (LLM simulation)
            if self.use_llm_simulation:
                output = self._simulate_llm_response(cmd, args, full_command)
            else:
                output = f"{cmd}: command not found\n"

        return output, mitre_mapping

    def _simulate_llm_response(self, cmd, args, full_command):
        """
        Simulates dynamic shell responses from an LLM.
        This provides a rich, believable deception response for commands like curl, wget, python, sudo, etc.
        """
        cmd_lower = cmd.lower()
        if cmd_lower in ["sudo", "su"]:
            return "Password: \n[sudo] password for admin: \nsudo: 3 incorrect password attempts\n"
        elif cmd_lower in ["curl", "wget"]:
            url = args[0] if args else "http://example.com"
            # Fake network delay / download progress simulation
            return (
                f"Connecting to {url}... connected.\n"
                f"HTTP request sent, awaiting response... 200 OK\n"
                f"Length: 104230 (101K) [application/octet-stream]\n"
                f"Saving to: '/tmp/{os.path.basename(url) or 'download'}'\n\n"
                f"100%[======================================>] 104,230     1.24MB/s   in 0.1s\n\n"
                f"2026-08-18 20:56:12 (1.24 MB/s) - '/tmp/{os.path.basename(url) or 'download'}' saved [104230/104230]\n"
            )
        elif cmd_lower in ["python", "python3"]:
            return (
                "Python 3.10.12 (main, Jun 11 2026, 05:26:28) [GCC 11.2.0] on linux\n"
                "Type \"help\", \"copyright\", \"credits\" or \"license\" for more information.\n"
                ">>> \n"
            )
        elif cmd_lower in ["docker", "kubectl"]:
            return (
                f"Cannot connect to the Docker daemon at unix:///var/run/docker.sock. "
                f"Is the docker daemon running?\n"
            )
        elif cmd_lower in ["nmap", "netstat", "ss"]:
            return (
                "Active Internet connections (only servers)\n"
                "Proto Recv-Q Send-Q Local Address           Foreign Address         State      \n"
                "tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN     \n"
                "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     \n"
                "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN     \n"
            )
        else:
            # Fallback mock shell behavior
            return f"-bash: {cmd}: command not found\n"
