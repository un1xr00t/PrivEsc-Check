# PrivEsc-Check

## Overview

**PrivEsc-Check** is a Python script designed to perform a basic privilege escalation scan on Linux systems. The script checks for common misconfigurations and potential vulnerabilities that could allow an attacker to gain elevated privileges.

## Features

- **SUID Binaries Check**: Scans the system for binaries with the SUID bit set, which could be exploited for privilege escalation.
- **Writable Files and Directories Check**: Identifies files and directories that are writable by the current user but owned by others.
- **Installed Packages Check**: (Placeholder) Checks installed packages for known vulnerabilities (this requires further implementation).
- **Weak Passwords Check**: Reads the `/etc/shadow` file to identify password hashes that could be cracked.
- **Sudoers File Check**: Analyzes the `/etc/sudoers` file for potential misconfigurations that could lead to privilege escalation.

## Usage

### Clone the Repository

```bash
git clone git@github.com:un1xr00t/PrivEsc-Check.git
cd PrivEsc-Check
