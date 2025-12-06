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
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_local_users(is_dc):
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

            if is_dc:
                new_list = result.stdout.splitlines()
                # when running get-localuser on dc, computers show up with a $ at the end of their name
                final_list = [x for x in new_list if not '$' in x]
                return final_list

            return result.stdout.splitlines()

        elif system_type == "Linux": 
            users = []
            with open("/etc/passwd", "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) > 2:
                        username = parts[0]
                        uid = int(parts[2])
                        if (uid >= 1000 or username == "root") and username != "nobody":
                            users.append(username)
            return users

        else:
            raise NotImplementedError(f"Unsupported OS: {system_type}")

    except Exception as e:
        print(f"Error retrieving users: {e}", file=sys.stderr)
        return []
    
def load_prev_info():
    system_type = platform.system()
    
    server_ip_address = "1.1.1.1"
    token = None

    if system_type == "Windows":
        dir_contnets = os.listdir("C:\\Program Files\\CCDC Password Manager")
        if "server_ip_address.txt" in dir_contnets:
            with open("C:\\Program Files\\CCDC Password Manager\\server_ip_address.txt", 'r') as file:
                server_ip_address = file.read().strip()
        if "token.txt" in dir_contnets:
            with open("C:\\Program Files\\CCDC Password Manager\\token.txt", 'r') as file:
                token = file.read().strip()
        
    elif system_type == "Linux":
        dir_contnets = os.listdir("/etc/ccdc_password_manager")
        
        if "server_ip_address" in dir_contnets:
            with open("/etc/ccdc_password_manager/server_ip_address", 'r') as file:
                server_ip_address = file.read().strip()
        if "token" in dir_contnets:
            with open("/etc/ccdc_password_manager/token", 'r') as file:
                token = file.read().strip()

    return (server_ip_address, token)

if __name__ == '__main__':
    system_type = platform.system()
    is_dc = False
    if system_type == "Windows":
        local_ip_address = subprocess.check_output(
            ["powershell.exe", "-c", "(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -like \"*Ethernet*\" }).IPAddress"],
            shell=True
        ).decode().strip()
        dc_detection = subprocess.run(
            ["powershell.exe", "-c", "Get-WmiObject -Query 'select * from Win32_OperatingSystem where (ProductType = \"2\")'"],
            shell=True,
            capture_output=True,
            text=True,
        )
        if dc_detection.stdout.strip() != "":
            is_dc = True

    elif system_type == "Linux":
        local_ip_address = subprocess.check_output(
            ["hostname", "-I"],
        ).decode().strip().split()[0]
        pass

    server_ip_address, prev_token = load_prev_info()
    token = ""
    if prev_token is not None:
        token = prev_token
    else:
        data = {
            'ip_address': local_ip_address,
        }
        output = requests.post(f'https://{server_ip_address}:443/register_client', verify=False, data=data)
        token = output.text
        
        if system_type == "Windows":
            with open("C:\\Program Files\\CCDC Password Manager\\token.txt", 'w') as file:
                file.write(token)
        elif system_type == "Linux":
            with open("/etc/ccdc_password_manager/token", 'w') as file:
                file.write(token)

    # get all local users on the system
    local_user_list = get_local_users(is_dc)
    i = 0

    data = {
        'local_users': ','.join(local_user_list),
        'ip_address': local_ip_address,
        'authoriztion_token': token
    }
    requests.post(f'https://{server_ip_address}:443/update_local_users', verify=False, data=data)

    while True:
        i += 1
        if i % 10 == 0:
            new_local_user_list = get_local_users(is_dc)
            if new_local_user_list != local_user_list:
                local_user_list = new_local_user_list
                diff = list(set(new_local_user_list).symmetric_difference(set(local_user_list)))

                data = {
                    'local_users': ','.join(diff),
                    'ip_address': local_ip_address,
                    'authoriztion_token': token
                }
                requests.post(f'https://{server_ip_address}:443/update_local_users', verify=False, data=data)
        

        data = {
            'ip_address': local_ip_address,
            'authoriztion_token': token
        }
        output = requests.post(f'https://{server_ip_address}:443/get_passwords_to_claim', verify=False, data=data)
        if output.text != "":
            user_passwords = output.json()
            if user_passwords['users'] != []:
                for user in user_passwords['users']:
                    if system_type == "Windows":
                        if is_dc:
                            pass
                        else:
                            subprocess.run(
                                ["powershell.exe", "-c", f"Set-LocalUser -Name \"{user['username']}\" -Password (ConvertTo-SecureString \"{user['password']}\" -AsPlainText -Force)"],
                                shell=True
                            )
                    elif system_type == "Linux":
                        subprocess.run(
                            ["sudo", "chpasswd"],
                            input=f"{user['username']}:{user['password']}",
                            text=True
                        )
        sleep(10)