"""
One-time setup: stores Exchange credentials securely in Windows Credential Manager.
Run this once from the command line:
    python exchange_alert_setup.py
"""

import keyring
import getpass

SERVICE_NAME = "ExchangeSecurityAlertMonitor"

print("=== Exchange Security Alert Monitor - Credential Setup ===")
print(f"Credentials will be stored in Windows Credential Manager under: {SERVICE_NAME}")
print()

username = input("Enter your Exchange username (e.g. con\x): ").strip()
password = getpass.getpass("Enter your Exchange password: ")

keyring.set_password(SERVICE_NAME, "username", username)
keyring.set_password(SERVICE_NAME, "password", password)

print()
print("Credentials stored successfully in Windows Credential Manager.")
print("You can view/edit them at any time via:")
print("  Control Panel > Credential Manager > Windows Credentials")
print(f"  Look for: {SERVICE_NAME}")
