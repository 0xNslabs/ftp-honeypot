import os
import argparse
from twisted.internet import reactor, protocol, endpoints
from twisted.protocols import basic
from twisted.python import log

script_dir = os.path.dirname(os.path.abspath(__file__))

class SimpleFTPProtocol(basic.LineReceiver):
    delimiter = b'\r\n'
    maxAttempts = 3

    def __init__(self):
        self.attempts = 0
        self.userReceived = False

    def connectionMade(self):
        client_ip = self.transport.getPeer().host
        client_port = self.transport.getPeer().port
        log.msg(f"FTP NEW Connection - Client IP: {client_ip}, Port: {client_port}")
        self.sendLine(b"220 Welcome to the FTP Honeypot")

    def lineReceived(self, line):
        log.msg(f"Received data: {line}")

        line_str = line.decode('utf-8')
        command = line_str.split(' ')[0].upper()

        if command == 'USER':
            self.userReceived = True
            self.sendLine(b"331 Username okay, need password")
        elif command == 'PASS' and self.userReceived:
            self.attempts += 1
            if self.attempts < self.maxAttempts:
                self.sendLine(b"530 Login incorrect")
                self.userReceived = False
            else:
                log.msg("Maximum attempts reached. Disconnecting client.")
                self.sendLine(b"530 Too many wrong attempts. Disconnecting.")
                self.transport.loseConnection()
        else:
            self.sendLine(b"500 Syntax error, command unrecognized")

    def sendLine(self, line):
        self.transport.write(line + self.delimiter)

    def connectionLost(self, reason):
        log.msg("Connection lost")

class SimpleFTPFactory(protocol.ServerFactory):
    protocol = SimpleFTPProtocol

def main():
    parser = argparse.ArgumentParser(description='Run a simple FTP honeypot server.')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to bind the FTP server to.')
    parser.add_argument('--port', type=int, default=2121, help='Port to bind the FTP server to.')
    args = parser.parse_args()

    LOG_FILE_PATH = os.path.join(script_dir, "ftp_honeypot.log")
    print(f"FTP HONEYPOT ACTIVE ON HOST: {args.host}, PORT: {args.port}")
    print(f"ALL attempts will be logged in: {LOG_FILE_PATH}")
    
    log_observer = log.FileLogObserver(open(LOG_FILE_PATH, 'a'))
    log.startLoggingWithObserver(log_observer.emit, setStdout=False)

    ftp_factory = SimpleFTPFactory()
    
    endpoint = endpoints.TCP4ServerEndpoint(reactor, args.port, interface=args.host)
    endpoint.listen(ftp_factory)
    reactor.run()

if __name__ == "__main__":
    main()