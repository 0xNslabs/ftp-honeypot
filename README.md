# Simple FTP Honeypot Server

## Introduction
The Simple FTP Honeypot Server is a lightweight script designed for cybersecurity practitioners looking to enhance network security. Crafted in Python with the Twisted library, this script establishes a low-interaction File Transfer Protocol (FTP) server, acting as a honeypot to log FTP access attempts and identify unauthorized activity.

## Features
- **Low-Interaction Honeypot**: Simulates an FTP service to safely capture and log access attempts.
- **Customizable Server Configuration**: Command-line arguments allow for easy adjustment of the host and port.
- **Detailed Logging**: Records every command sent to the FTP server, aiding in security analysis.
- **Real-time Interaction**: Offers real-time engagement with clients, capturing credentials and commands.
- **Educational and Research Tool**: Ideal for studying FTP-based attack patterns and for educational purposes.

## Requirements
- Python 3.x
- Twisted Python library

## Installation
To get started with the FTP honeypot server, follow these steps:

```bash
git clone https://github.com/0xNslabs/ftp-honeypot.git
cd ftp-honeypot
pip install twisted
```

## Usage

Run the script using the following command with optional arguments for host and port. It defaults to 0.0.0.0 (all interfaces) and port 2121.


```bash
python3 sip.py --host 0.0.0.0 --port 2121
```

## Logging

The FTP interactions are recorded in `ftp_honeypot.log`, which includes details about every login attempt and command issued to the server.

## Simple FTP Honeypot In Action

![Simple FTP Honeypot in Action](https://raw.githubusercontent.com/0xNslabs/ftp-honeypot/main/PoC.png)
*The above image showcases the Simple FTP Honeypot server capturing login attempts.*

## Other Simple Honeypot Services

Check out the other honeypot services for monitoring various network protocols:

- [DNS Honeypot](https://github.com/0xNslabs/dns-honeypot) - Monitors DNS interactions.
- [FTP Honeypot](https://github.com/0xNslabs/ftp-honeypot) - Simulates an FTP server.
- [LDAP Honeypot](https://github.com/0xNslabs/ldap-honeypot) - Mimics an LDAP server.
- [NTP Honeypot](https://github.com/0xNslabs/ntp-honeypot) - Monitors Network Time Protocol interactions.
- [PostgreSQL Honeypot](https://github.com/0xNslabs/postgresql-honeypot) - Simulates a PostgreSQL database server.
- [SIP Honeypot](https://github.com/0xNslabs/sip-honeypot) - Monitors SIP (Session Initiation Protocol) interactions.
- [SSH Honeypot](https://github.com/0xNslabs/ssh-honeypot) - Emulates an SSH server.
- [TELNET Honeypot](https://github.com/0xNslabs/telnet-honeypot) - Simulates a TELNET server.

## Security and Compliance
- **Caution**: As a honeypot, this server should be deployed in a controlled environment.
- **Compliance**: Ensure compliance with all applicable local and international laws when deploying the honeypot.

## License
This project is distributed under the MIT License. See `LICENSE` for more information.