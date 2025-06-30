#!/usr/bin/env python3
"""Simple SMTP honeypot server."""

import argparse
import json
import logging
import socketserver
import sys
import syslog
import time

DEFAULT_CONFIG = "/var/local/mailpot/smtp_profile.json"


class SMTPHandler(socketserver.StreamRequestHandler):
    """Handle SMTP interactions based on a JSON profile."""

    def handle(self) -> None:
        peer = self.connection.getpeername()
        syslog.syslog(syslog.LOG_INFO, "[smtp-honeypot] Connection from {}:{}".format(peer[0], peer[1]))
        self.server.logger.info("Connection from %s:%s", peer[0], peer[1])

        def send(line: str) -> None:
            self.wfile.write((line + "\r\n").encode("utf-8"))

        def expect() -> str:
            return self.rfile.readline().decode("utf-8", errors="ignore").strip()

        profile = self.server.profile
        send(profile.get("banner", "220 mail.local ESMTP ready"))

        while True:
            try:
                line = expect()
                if not line:
                    break
                cmd = line.split()[0].upper()

                if cmd == "AUTH" and "LOGIN" in line:
                    send(profile.get("AUTH LOGIN", "334 VXNlcm5hbWU6"))
                    expect()  # username
                    send(profile.get("AUTH LOGIN user", "334 UGFzc3dvcmQ6"))
                    expect()  # password
                    time.sleep(self.server.fail_delay)
                    send(profile.get("AUTH LOGIN pass", "535 5.7.8 Error: authentication failed"))
                elif cmd == "AUTH" and "PLAIN" in line:
                    time.sleep(self.server.fail_delay)
                    send(profile.get("AUTH PLAIN", "535 5.7.8 Error: authentication failed"))
                elif cmd == "DATA":
                    send(profile.get("DATA", "354 End data with <CR><LF>.<CR><LF>"))
                    while True:
                        l = expect()
                        if l == ".":
                            break
                    send(profile.get("DATA body", "250 Ok"))
                elif cmd == "QUIT":
                    send(profile.get("QUIT", "221 Bye"))
                    break
                else:
                    key = line if line in profile else cmd
                    send(profile.get(key, "502 5.5.2 Command not recognized"))
            except Exception as exc:  # pragma: no cover - logging
                msg = "[smtp-honeypot] Error: {}".format(exc)
                syslog.syslog(syslog.LOG_ERR, msg)
                self.server.logger.error(msg)
                break


class SMTPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self, addr, handler, profile: dict, fail_delay: int, logger: logging.Logger):
        super().__init__(addr, handler)
        self.profile = profile
        self.fail_delay = fail_delay
        self.logger = logger


def load_profile(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="SMTP Honeypot Daemon")
    parser.add_argument("--host", default="0.0.0.0", help="Listen address")
    parser.add_argument("--port", type=int, default=25, help="Listen port")
    parser.add_argument("--config", default=DEFAULT_CONFIG, help="Path to SMTP profile JSON")
    parser.add_argument("--fail-delay", type=int, default=3, help="Delay in seconds after failed AUTH")
    args = parser.parse_args(argv)

    logger = logging.getLogger("smtp-honeypot")
    logging.basicConfig(level=logging.INFO)

    profile = load_profile(args.config)

    server = SMTPServer((args.host, args.port), SMTPHandler, profile, args.fail_delay, logger)

    logger.info("Starting SMTP honeypot on %s:%s", args.host, args.port)
    syslog.openlog("smtp-honeypot")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
