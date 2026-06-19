# Exchange Security Alert Monitor

A Python utility that monitors an on-premises Microsoft Exchange inbox for critical security alerts, parses their contents, and triggers immediate alerts via email when specific criteria (e.g., "attack detected but not blocked") are matched.

To protect sensitive login information, the monitor stores credentials securely in the Windows Credential Manager rather than in plain-text configuration files.

---

## Features

- **OWA Form-Based Authentication:** Logs into Exchange via Outlook Web Access (OWA) form-based login.
- **Exchange REST API Integration:** Utilizes the `/api/v2.0` Exchange REST API to retrieve inbox messages.
- **Secure Credential Storage:** Uses the Python `keyring` library to securely save and retrieve credentials from the Windows Credential Manager.
- **De-duplication:** Tracks already processed messages using a local JSON file (`exchange_alert_processed.json`) to prevent duplicate alert notifications.
- **Custom SMTP Alerts:** Sends email alerts immediately when a security issue matches the search parameters.

---

## Prerequisites

- **OS:** Windows (required for the Windows Credential Manager keyring backend, unless configured otherwise).
- **Python:** Version 3.6 or higher.
- **Packages:** Install dependencies using pip:
  ```bash
  pip install requests requests_ntlm keyring urllib3
  ```

---

## Setup & Configuration

### 1. Configure the Application
Create a file named `exchange_alert_config.json` in the root of the project (this file is excluded from Git). Use the following format:

```json
{
  "exchange_server": "messaging.xpandcorp.com",
  "mailbox": "giri.dronam@xpandcorp.com",
  "alert_to": "hostmaster@xpandcorp.com",
  "smtp_server": "messaging.xpandcorp.com",
  "smtp_port": 587
}
```

**Configuration Fields:**
- `exchange_server`: The hostname of your Exchange server (used for OWA login and the REST API).
- `mailbox`: The email address from which the script will access the mailbox and send SMTP notifications.
- `alert_to`: The recipient email address for security alert notifications.
- `smtp_server` (Optional): The SMTP server hostname. Defaults to `exchange_server` if not specified.
- `smtp_port` (Optional): The SMTP port. Defaults to `587`.

### 2. Store Credentials Securely
Run the setup script to store your Exchange username and password in Windows Credential Manager:

```bash
python exchange_alert_setup.py
```

You will be prompted to enter:
- **Exchange username** (e.g., `XPANDCORP\giri.dronam` or `giri.dronam@xpandcorp.com`)
- **Exchange password** (masked during typing)

The credentials will be securely saved under the service name `ExchangeSecurityAlertMonitor`. You can view or delete these credentials via:
`Control Panel > Credential Manager > Windows Credentials`.

---

## Usage

Run the monitor script:

```bash
python exchange_security_alert.py
```

### Automation (Windows Task Scheduler)
To run this script automatically at regular intervals:
1. Open **Task Scheduler** and select **Create Basic Task**.
2. Set the trigger (e.g., **Daily** or **Repeated every 5 minutes**).
3. Set the action to **Start a Program**.
4. Set the **Program/script** to your Python path (e.g., `python` or the full path to your virtual environment's python executable).
5. Set **Add arguments** to the full path of the script (e.g., `C:\scripts\Read_emails\exchange_security_alert.py`).
6. Set **Start in** to the script directory (`C:\scripts\Read_emails\`).

---

## File Structure

- [exchange_security_alert.py](file:///c:/scripts/Read_emails/exchange_security_alert.py) - Main monitor script that searches emails and sends alerts.
- [exchange_alert_setup.py](file:///c:/scripts/Read_emails/exchange_alert_setup.py) - Initial setup utility to store credentials.
- `exchange_alert_config.json` - Server and alert recipient configuration (local only, ignored by Git).
- `exchange_alert_processed.json` - Persistent state storing IDs of already processed alerts (local only, ignored by Git).
- [.gitignore](file:///c:/scripts/Read_emails/.gitignore) - Excludes Python caches and configuration files from Git repositories.
