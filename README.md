# Simple FTP Honeypot Server

## Introduction
The Simple FTP Honeypot Server is a lightweight low-interaction FTP service built with Python and Twisted. It is designed for defenders and researchers who want to safely observe FTP probing, brute-force attempts, and command patterns while collecting actionable logs for incident response and threat hunting.

## Features
- **Low-Interaction Honeypot**: Simulates an FTP control channel to capture attacker behavior without exposing a real filesystem.
- **Configurable Banner**: Set a custom `220` welcome message via `--banner`.
- **Raw Bytes Telemetry**: Logs raw inbound bytes (length + hex preview) in addition to parsed commands to help detect malformed payloads and potential zero-days.
- **Better Protocol Fidelity**: Handles common FTP commands (e.g., `SYST`, `FEAT`, `TYPE`, `NOOP`, `HELP`, `QUIT`) and returns realistic response codes.
- **Credential Capture**: Records USER/PASS attempts and enforces a configurable attempt limit (default: 3).
- **Clear Logging**: Writes all activity to `ftp_honeypot.log` for later analysis.

## Requirements
- Python 3.x
- Twisted (`pip install twisted`)

## Installation
```bash
git clone https://github.com/0xNslabs/ftp-honeypot.git
cd ftp-honeypot
pip install twisted
```

## Usage
Run the server (defaults: `0.0.0.0:2121`):
```bash
python3 ftp.py --host 0.0.0.0 --port 2121
```

Set a custom banner (status code is enforced as `220`):
```bash
python3 ftp.py --host 0.0.0.0 --port 2121 --banner "220 vsFTPd 3.0.3 ready"
```

## Logging
All interactions are recorded in `ftp_honeypot.log`. Logs include:
- New connections (client IP/port)
- Raw inbound byte telemetry (length + hex preview)
- Parsed FTP commands
- Captured credentials (USER/PASS attempts)
- Disconnect events

## Simple FTP Honeypot In Action
![Simple FTP Honeypot in Action](https://raw.githubusercontent.com/0xNslabs/ftp-honeypot/main/PoC.png)
*The above image showcases the Simple FTP Honeypot server capturing login attempts.*

## Other Simple Honeypot Services
- [DNS Honeypot](https://github.com/0xNslabs/dns-honeypot) - Monitors DNS interactions.
- [FTP Honeypot](https://github.com/0xNslabs/ftp-honeypot) - Simulates an FTP server.
- [LDAP Honeypot](https://github.com/0xNslabs/ldap-honeypot) - Mimics an LDAP server.
- [HTTP Honeypot](https://github.com/0xNslabs/http-honeypot) - Monitors HTTP interactions.
- [HTTPS Honeypot](https://github.com/0xNslabs/https-honeypot) - Monitors HTTPS interactions.
- [MongoDB Honeypot](https://github.com/0xNslabs/mongodb-honeypot) - Simulates a MongoDB database server.
- [NTP Honeypot](https://github.com/0xNslabs/ntp-honeypot) - Monitors Network Time Protocol interactions.
- [PostgreSQL Honeypot](https://github.com/0xNslabs/postgresql-honeypot) - Simulates a PostgreSQL database server.
- [SIP Honeypot](https://github.com/0xNslabs/sip-honeypot) - Monitors SIP (Session Initiation Protocol) interactions.
- [SSH Honeypot](https://github.com/0xNslabs/ssh-honeypot) - Emulates an SSH server.
- [TELNET Honeypot](https://github.com/0xNslabs/telnet-honeypot) - Simulates a TELNET server.

## Security and Compliance
- **Caution**: Deploy in a controlled environment (e.g., isolated VLAN, VM, or lab segment). Do not expose to sensitive internal networks without segmentation and monitoring.
- **Compliance**: Ensure compliance with all applicable local and international laws when deploying the honeypot.

## License
This project is distributed under the MIT License. See `LICENSE` for more information.
