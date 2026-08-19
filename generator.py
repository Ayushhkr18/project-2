import random
import uuid
import hashlib

class GenerativeContentEngine:
    def __init__(self, seed=None):
        if seed:
            random.seed(seed)
        
        self.companies = ["NexusTech", "ApexFinancial", "CyberShield", "AlphaLogistics"]
        self.company = random.choice(self.companies)
        self.departments = ["Finance", "Engineering", "HR", "Legal", "Operations"]
        
        self.first_names = ["John", "Sarah", "Michael", "Emily", "David", "Jessica", "Robert", "Ashley", "James", "Amanda"]
        self.last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez"]
        
        self.tech_stacks = ["Kubernetes/AWS", "On-Premises VMware", "Azure/ActiveDirectory", "Hybrid Cloud"]
        self.tech_stack = random.choice(self.tech_stacks)

    def generate_username(self):
        first = random.choice(self.first_names).lower()
        last = random.choice(self.last_names).lower()
        formats = [
            f"{first}.{last}",
            f"{first[0]}{last}",
            f"{first}{last[0]}",
            f"{last}_{first}"
        ]
        return random.choice(formats)

    def generate_honeytoken_credential(self, cred_type="aws"):
        """
        Generates realistic-looking credentials that serve as honeytokens.
        These are registered in our session state so any attempt to use or leak them will flag alerts.
        """
        if cred_type == "aws":
            key_id = "AKIA" + "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=16))
            secret = "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+", k=40))
            return {
                "type": "AWS IAM Key",
                "identity": key_id,
                "secret": secret,
                "instructions": "Do not share. Production AWS administrator access."
            }
        elif cred_type == "database":
            db_names = ["prod_users", "client_ledger", "transactions_v4", "billing_db"]
            db_users = ["db_admin", "app_sync", "postgres", "sa"]
            password = "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$", k=14))
            port = random.choice([5432, 3306, 1433, 27017])
            host = f"db-internal.{self.company.lower()}.local"
            return {
                "type": "Database Connection String",
                "host": host,
                "port": port,
                "database": random.choice(db_names),
                "username": random.choice(db_users),
                "password": password,
                "conn_str": f"postgresql://{random.choice(db_users)}:{password}@{host}:{port}/{random.choice(db_names)}"
            }
        elif cred_type == "ssh":
            # Generate a fake RSA Private Key header/footer with randomized body
            body_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+\n"
            fake_body = "".join(random.choices(body_chars, k=180))
            # Format nicely
            lines = [fake_body[i:i+64] for i in range(0, len(fake_body), 64)]
            formatted_body = "\n".join(lines)
            key_content = f"-----BEGIN RSA PRIVATE KEY-----\n{formatted_body}\n-----END RSA PRIVATE KEY-----"
            return {
                "type": "SSH Private Key",
                "identity": f"{self.generate_username()}@internal-bastion",
                "secret": key_content,
                "instructions": "Private key for remote administration node"
            }
        else:
            # Default API Token
            token = "sk_live_" + "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=32))
            return {
                "type": "API Key",
                "identity": "Stripe Live API Gateway",
                "secret": token,
                "instructions": "Production billing gateway endpoint token"
            }

    def generate_document_content(self, filename):
        """
        Generates realistic content for honeypot documents based on the filename.
        """
        filename_lower = filename.lower()
        if "pass" in filename_lower or "cred" in filename_lower or "auth" in filename_lower:
            # Plant some credential files
            aws_cred = self.generate_honeytoken_credential("aws")
            db_cred = self.generate_honeytoken_credential("database")
            return (
                f"# INTERNAL ACCESS CONFIGURATIONS - {self.company.upper()} SECURITY GATEWAY\n"
                f"# WARNING: CLASSIFIED CONTENT. UNAUTHORIZED USE IS STRICTLY MONITORED.\n\n"
                f"[aws_prod_env]\n"
                f"aws_access_key_id = {aws_cred['identity']}\n"
                f"aws_secret_access_key = {aws_cred['secret']}\n\n"
                f"[database_replica]\n"
                f"connection_uri = {db_cred['conn_str']}\n"
            )
        elif "back" in filename_lower or "dump" in filename_lower or "sql" in filename_lower:
            return (
                f"-- PostgreSQL database dump\n"
                f"-- Dumped from database version 14.2\n"
                f"-- Structure and client data backup for recovery operations\n\n"
                f"CREATE TABLE users (\n"
                f"    id SERIAL PRIMARY KEY,\n"
                f"    username VARCHAR(50) NOT NULL UNIQUE,\n"
                f"    password_hash VARCHAR(64) NOT NULL,\n"
                f"    email VARCHAR(100),\n"
                f"    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n"
                f");\n\n"
                f"INSERT INTO users (username, password_hash, email) VALUES\n"
                f"('admin', '$2b$12$N9qo8uLOqpGCV2vuyr1tG.X.gGv7tG6s5H9u7Y8Y5k7l8m9n0o1p2', 'admin@{self.company.lower()}.com'),\n"
                f"('service_sync', '$2b$12$R8qj1uLOqpGCV2vuyr1tG.X.gGv7tG6s5H9u7Y8Y5k7l8m9n0o1p2', 'sync@{self.company.lower()}.com');\n"
            )
        elif "confidential" in filename_lower or "internal" in filename_lower or "financial" in filename_lower:
            return (
                f"==============================================================\n"
                f"               {self.company.upper()} INTERNAL MEMO - CONFIDENTIAL\n"
                f"==============================================================\n"
                f"TO: All Core Technical Infrastructure Lead Developers\n"
                f"FROM: Operations & Architecture Command Center\n"
                f"DATE: August 2026\n"
                f"SUBJECT: Network Segment Migration and Access Keys Protection\n\n"
                f"This document outlines the migration schedule to the new cloud infrastructure.\n"
                f"Ensure all local Docker runtimes are shut down by the end of this cycle.\n"
                f"For SSH authentication, please refer to internal keys located at /home/admin/.ssh/\n"
            )
        elif "todo" in filename_lower or "notes" in filename_lower:
            return (
                f"TODO LIST - DEPLOYMENT DEVOPS NODE:\n"
                f"1. Fix database replicas auto-failover scripts\n"
                f"2. Rotate outdated AWS production root access tokens\n"
                f"3. Audit internal filesystems for unencrypted credential dumps\n"
                f"4. Deploy backup client gateway server\n"
            )
        else:
            return (
                f"# Welcome to {self.company} Core Server Node\n"
                f"This server is part of the internal staging/production platform.\n"
                f"Unauthorized activities will be logged and reported immediately.\n"
                f"System administrator contact: admin@{self.company.lower()}.com\n"
            )
