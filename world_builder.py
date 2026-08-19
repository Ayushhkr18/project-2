import os
import random
from generator import GenerativeContentEngine

class VirtualFilesystemBuilder:
    def __init__(self, generator: GenerativeContentEngine):
        self.gen = generator
        self.fs = {}
        self.honeytokens = []
        self._build_default_filesystem()

    def _build_default_filesystem(self):
        # Base Linux Directory Layout
        dirs = [
            "/",
            "/bin",
            "/sbin",
            "/etc",
            "/etc/ssh",
            "/var",
            "/var/log",
            "/var/www",
            "/var/www/html",
            "/var/www/html/config",
            "/home",
            "/home/admin",
            "/home/admin/.ssh",
            "/root",
            "/tmp"
        ]
        
        for d in dirs:
            self.fs[d] = {"type": "directory", "children": {}}

        # Establish parent-child directory tree relationships
        for d in dirs:
            if d == "/":
                continue
            parent = os.path.dirname(d).replace("\\", "/")
            name = os.path.basename(d)
            if parent == "":
                parent = "/"
            self.fs[parent]["children"][name] = {"type": "directory"}

        # Generate decoy files and plant them in the Virtual FS
        self._add_file("/etc/issue", f"Ubuntu 22.04.4 LTS \\n \\l\n\nWelcome to staging-deployment-server ({self.gen.tech_stack})\n")
        self._add_file("/etc/hostname", f"staging-node-03.{self.gen.company.lower()}.local\n")
        self._add_file("/etc/passwd", (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
            "sync:x:4:65534:sync:/bin:/bin/sync\n"
            "admin:x:1000:1000:Administrator:/home/admin:/bin/bash\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        ))
        
        self._add_file("/etc/shadow", (
            "root:*:19120:0:99999:7:::\n"
            "daemon:*:19120:0:99999:7:::\n"
            "bin:*:19120:0:99999:7:::\n"
            "sys:*:19120:0:99999:7:::\n"
            "sync:*:19120:0:99999:7:::\n"
            "admin:$6$p2.7qR9i$XFfVqT99N1hY8aJg92jVz/qT3H6qY8Y5k7l8m9n0o1p2q3r4s5t6u7v8w9x0y1z2:19120:0:99999:7:::\n"
        ))

        # Generate honeytoken credentials
        aws_token = self.gen.generate_honeytoken_credential("aws")
        db_token = self.gen.generate_honeytoken_credential("database")
        ssh_token = self.gen.generate_honeytoken_credential("ssh")
        api_token = self.gen.generate_honeytoken_credential("api")
        
        self.honeytokens.extend([aws_token, db_token, ssh_token, api_token])

        # Plant credentials in realistic config directories
        self._add_file("/home/admin/.ssh/authorized_keys", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC3d... admin@nexus-deployer\n")
        self._add_file("/home/admin/.ssh/id_rsa", ssh_token["secret"])
        
        self._add_file("/var/www/html/config/database.yml", (
            "production:\n"
            "  adapter: postgresql\n"
            f"  host: {db_token['host']}\n"
            f"  port: {db_token['port']}\n"
            f"  database: {db_token['database']}\n"
            f"  username: {db_token['username']}\n"
            f"  password: \"{db_token['password']}\"\n"
            "  pool: 15\n"
        ))
        
        self._add_file("/home/admin/.aws/credentials", (
            "[default]\n"
            f"aws_access_key_id = {aws_token['identity']}\n"
            f"aws_secret_access_key = {aws_token['secret']}\n"
        ))

        self._add_file("/var/www/html/index.html", f"<html><body><h1>Staging Node - Under Maintenance</h1></body></html>\n")
        self._add_file("/home/admin/todo.txt", self.gen.generate_document_content("todo.txt"))
        self._add_file("/home/admin/confidential_memo.txt", self.gen.generate_document_content("confidential_memo.txt"))
        
        # Plant bash history leading attackers towards the honeytokens
        self._add_file("/home/admin/.bash_history", (
            "cd /var/www/html/config\n"
            "cat database.yml\n"
            "ssh-keygen -t rsa -b 4096\n"
            "mv id_rsa ~/.ssh/\n"
            "aws configure\n"
            "cat ~/.aws/credentials\n"
            "ls -la /home/admin/\n"
            "exit\n"
        ))

    def _add_file(self, filepath, content):
        parent = os.path.dirname(filepath).replace("\\", "/")
        name = os.path.basename(filepath)
        if parent == "":
            parent = "/"
        
        self.fs[filepath] = {
            "type": "file",
            "content": content,
            "size": len(content)
        }
        
        if parent in self.fs:
            self.fs[parent]["children"][name] = {"type": "file"}

    def write_file_content(self, filepath, content):
        self._add_file(filepath, content)

    def read_file_content(self, filepath):
        if filepath in self.fs and self.fs[filepath]["type"] == "file":
            return self.fs[filepath]["content"]
        return None

    def exists(self, path):
        return path in self.fs

    def is_dir(self, path):
        return path in self.fs and self.fs[path]["type"] == "directory"

    def is_file(self, path):
        return path in self.fs and self.fs[path]["type"] == "file"

    def list_dir(self, path):
        if self.is_dir(path):
            return list(self.fs[path]["children"].keys())
        return []

    def get_fs_tree(self, current_dir="/", indent=0):
        """
        Returns a JSON structure representing the file tree structure
        for displaying in the dashboard file explorer.
        """
        tree = []
        for name, item in sorted(self.fs[current_dir]["children"].items()):
            full_path = os.path.join(current_dir, name).replace("\\", "/")
            if current_dir == "/":
                full_path = "/" + name
            
            node = {
                "name": name,
                "type": item["type"],
                "path": full_path
            }
            if item["type"] == "directory":
                node["children"] = self.get_fs_tree(full_path, indent + 1)
            else:
                node["size"] = self.fs[full_path]["size"]
            tree.append(node)
        return tree
