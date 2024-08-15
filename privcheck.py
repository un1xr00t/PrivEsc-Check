#!/usr/bin/env python3

import os
import subprocess

def print_banner():
    banner = """
___  ____ _ _  _ ____ ____ ____    ____ _  _ ____ ____ _  _ 
|__] |__/ | |  | |___ [__  |       |    |__| |___ |    |_/  
|    |  \\ |  \\/  |___ ___] |___    |___ |  | |___ |___ | \\_ 
                                                            
    """
    print(f"\033[94m{banner}\033[0m")  # Prints the banner in blue

def run_command(command):
    try:
        # Redirecting stderr to /dev/null to suppress error messages
        result = subprocess.check_output(command, shell=True, stderr=subprocess.DEVNULL).decode().splitlines()
        return result
    except subprocess.CalledProcessError as e:
        # If the command fails, just return an empty list to indicate no results
        return []

def check_suid_binaries():
    print("[*] Scanning for SUID binaries...")
    suid_binaries = run_command("find / -perm -4000 -type f 2>/dev/null")
    if suid_binaries:
        print("[+] SUID binaries found:")
        for binary in suid_binaries:
            print(f"    {binary}")
    else:
        print("[-] No SUID binaries found or unable to scan.")

def check_writable_files_and_directories():
    print("[*] Scanning for writable files and directories...")
    writable_files = run_command("find / -writable ! -user $(whoami) ! -type l 2>/dev/null")
    if writable_files:
        print("[+] Writable files and directories found:")
        for file in writable_files:
            print(f"    {file}")
    else:
        print("[-] No writable files or directories found or unable to scan.")

def check_installed_packages():
    print("[*] Checking for installed packages with known vulnerabilities...")
    installed_packages = run_command("dpkg -l 2>/dev/null")
    vulnerable_packages = []
    for package in installed_packages:
        package_info = package.split()
        if len(package_info) > 1:
            package_name = package_info[1]
            # Placeholder: Add real vulnerability check here
        else:
            continue

    if vulnerable_packages:
        print("[+] Vulnerable packages found:")
        for package in vulnerable_packages:
            print(f"    {package}")
    else:
        print("[-] No vulnerable packages found.")

def check_for_weak_passwords():
    print("[*] Checking for weak passwords...")
    try:
        with open('/etc/shadow', 'r') as shadow_file:
            shadow_content = shadow_file.read().splitlines()

        for line in shadow_content:
            if not line.startswith('#'):
                user_data = line.split(':')
                username = user_data[0]
                password_hash = user_data[1]

                if password_hash in ['*', '!', 'x']:
                    continue

                # Placeholder for password cracking tool integration
                if username.startswith("systemd-") or username in ["fwupd-refresh", "polkitd", "gnome-remote-desktop"]:
                    print(f"[!] System account {username} has a password hash.")
                else:
                    print(f"[+] User {username} has a password hash that could be cracked.")
    except PermissionError as e:
        print(f"[!] Permission denied: {e}")
    except Exception as e:
        print(f"[!] Error reading /etc/shadow: {e}")

def check_sudoers_file():
    print("[*] Checking sudoers file for misconfigurations...")
    sudoers_content = run_command("cat /etc/sudoers 2>/dev/null")
    if sudoers_content:
        for line in sudoers_content:
            if line.startswith('%') or 'ALL' in line:
                print(f"[+] Possible sudoers misconfiguration: {line.strip()}")
    else:
        print("[-] No sudoers file issues found or unable to read sudoers file.")

def main():
    print_banner()  # Print the banner at the start
    if os.geteuid() != 0:
        print("[!] This script requires root privileges to run effectively.")
        exit(1)

    check_suid_binaries()
    check_writable_files_and_directories()
    check_installed_packages()
    check_for_weak_passwords()
    check_sudoers_file()

    print("[*] Privilege escalation scan completed.")

if __name__ == "__main__":
    main()
