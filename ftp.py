import os
import argparse
from twisted.internet import reactor, protocol, endpoints
from twisted.protocols import basic
from twisted.python import log


script_dir = os.path.dirname(os.path.abspath(__file__))
BANNER = b"220 Welcome to the FTP Honeypot"


def _safe_ascii(s: bytes) -> str:
    try:
        return s.decode("ascii", "replace")
    except Exception:
        try:
            return s.decode("utf-8", "replace")
        except Exception:
            return repr(s)


def _hex_preview(b: bytes, limit: int = 512) -> str:
    if not b:
        return ""
    n = min(len(b), int(limit))
    hx = b[:n].hex()
    if len(b) > n:
        return f"{hx}...(truncated,{len(b)}B)"
    return hx


class SimpleFTPProtocol(basic.LineReceiver):
    delimiter = b"\n"
    maxAttempts = 3

    def __init__(self):
        self.attempts = 0
        self.userReceived = False
        self.username = ""
        self._out_delim = b"\r\n"

    def connectionMade(self):
        client_ip = self.transport.getPeer().host
        client_port = self.transport.getPeer().port
        log.msg(f"FTP NEW Connection - Client IP: {client_ip}, Port: {client_port}")
        self.sendLine(BANNER)

    def dataReceived(self, data: bytes):
        try:
            log.msg(f"Received raw bytes len={len(data)} hex={_hex_preview(data)}")
        except Exception:
            pass
        return super().dataReceived(data)

    def lineLengthExceeded(self, line: bytes):
        try:
            log.msg(f"Received raw bytes len={len(line)} hex={_hex_preview(line)}")
        except Exception:
            pass
        self.sendLine(b"500 Syntax error, command unrecognized")
        self.transport.loseConnection()

    def lineReceived(self, line: bytes):
        if line.endswith(b"\r"):
            line = line[:-1]

        log.msg(f"Received data: {line}")

        raw = line.strip()
        if not raw:
            self.sendLine(b"500 Syntax error, command unrecognized")
            return

        parts = raw.split(None, 1)
        verb = (parts[0] or b"").upper()
        arg = parts[1] if len(parts) > 1 else b""

        if verb == b"QUIT":
            self.sendLine(b"221 Goodbye.")
            self.transport.loseConnection()
            return

        if verb == b"NOOP":
            self.sendLine(b"200 NOOP ok.")
            return

        if verb == b"SYST":
            self.sendLine(b"215 UNIX Type: L8")
            return

        if verb == b"FEAT":
            self.sendLine(b"211-Features:")
            self.sendLine(b" UTF8")
            self.sendLine(b" EPSV")
            self.sendLine(b" EPRT")
            self.sendLine(b" MDTM")
            self.sendLine(b" SIZE")
            self.sendLine(b" MLST type*;size*;modify*;perm*;")
            self.sendLine(b"211 End")
            return

        if verb == b"HELP":
            self.sendLine(b"214 Supported commands: USER PASS SYST FEAT TYPE OPTS CLNT NOOP HELP QUIT")
            return

        if verb == b"TYPE":
            t = _safe_ascii(arg).strip().upper()
            if t in ("A", "I"):
                self.sendLine(b"200 Type set.")
            else:
                self.sendLine(b"501 Syntax error in parameters or arguments.")
            return

        if verb == b"OPTS":
            self.sendLine(b"200 OPTS ok.")
            return

        if verb == b"CLNT":
            self.sendLine(b"200 CLNT ok.")
            return

        if verb == b"AUTH":
            self.sendLine(b"502 Command not implemented.")
            return

        if verb in (b"PBSZ", b"PROT"):
            self.sendLine(b"503 Bad sequence of commands.")
            return

        if verb == b"REIN":
            self.attempts = 0
            self.userReceived = False
            self.username = ""
            self.sendLine(b"220 Service ready for new user.")
            return

        if verb == b"USER":
            u = _safe_ascii(arg).strip()
            self.username = u
            self.userReceived = True
            self.sendLine(b"331 Username okay, need password")
            return

        if verb == b"PASS":
            if not self.userReceived:
                self.sendLine(b"503 Bad sequence of commands.")
                return

            p = _safe_ascii(arg)
            self.attempts += 1

            try:
                log.msg(f"Captured credentials - USER: {self.username} PASS: {p}")
            except Exception:
                pass

            if self.attempts < self.maxAttempts:
                self.sendLine(b"530 Login incorrect")
                self.userReceived = False
            else:
                log.msg("Maximum attempts reached. Disconnecting client.")
                self.sendLine(b"530 Too many wrong attempts. Disconnecting.")
                self.transport.loseConnection()
            return

        if verb in (
            b"PWD",
            b"CWD",
            b"CDUP",
            b"LIST",
            b"NLST",
            b"MLSD",
            b"MLST",
            b"RETR",
            b"STOR",
            b"APPE",
            b"STOU",
            b"DELE",
            b"RMD",
            b"RNFR",
            b"RNTO",
            b"MKD",
            b"MDTM",
            b"SIZE",
            b"PASV",
            b"EPSV",
            b"PORT",
            b"EPRT",
            b"REST",
            b"ABOR",
            b"SITE",
        ):
            self.sendLine(b"530 Not logged in.")
            return

        self.sendLine(b"500 Syntax error, command unrecognized")

    def sendLine(self, line: bytes):
        self.transport.write(line + self._out_delim)

    def connectionLost(self, reason):
        log.msg("Connection lost")


class SimpleFTPFactory(protocol.ServerFactory):
    protocol = SimpleFTPProtocol


def main():
    global BANNER

    parser = argparse.ArgumentParser(description="Run a simple FTP honeypot server.")
    parser.add_argument(
        "--host", type=str, default="0.0.0.0", help="Host to bind the FTP server to."
    )
    parser.add_argument(
        "--port", type=int, default=2121, help="Port to bind the FTP server to."
    )
    parser.add_argument(
        "--banner",
        type=str,
        default="220 Welcome to the FTP Honeypot",
        help="FTP banner line to send on connect (status code + text).",
    )
    args = parser.parse_args()

    banner_str = (args.banner or "").rstrip("\r\n")
    if not banner_str:
        banner_str = "220 Welcome to the FTP Honeypot"
    if not banner_str.startswith("220 "):
        banner_str = "220 " + banner_str
    BANNER = banner_str.encode("utf-8", "replace")

    LOG_FILE_PATH = os.path.join(script_dir, "ftp_honeypot.log")
    print(f"FTP HONEYPOT ACTIVE ON HOST: {args.host}, PORT: {args.port}")
    print(f"ALL attempts will be logged in: {LOG_FILE_PATH}")

    log_observer = log.FileLogObserver(open(LOG_FILE_PATH, "a"))
    log.startLoggingWithObserver(log_observer.emit, setStdout=False)

    ftp_factory = SimpleFTPFactory()

    endpoint = endpoints.TCP4ServerEndpoint(reactor, args.port, interface=args.host)
    endpoint.listen(ftp_factory)
    reactor.run()


if __name__ == "__main__":
    main()
