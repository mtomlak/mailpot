#!/usr/bin/env python3
"""Simple POP3 honeypot server."""

import argparse
import json
import logging
import socketserver
import sys
import syslog
import time

DEFAULT_CONFIG = "/var/local/mailpot/pop3_profile.json"


class POP3Handler(socketserver.StreamRequestHandler):
    """Handle POP3 interactions based on a JSON profile."""

    def handle(self) -> None:
        peer = self.connection.getpeername()
        syslog.syslog(syslog.LOG_INFO, "[pop3-honeypot] Connection from {}:{}".format(peer[0], peer[1]))
        self.server.logger.info("Connection from %s:%s", peer[0], peer[1])

        def send(line: str) -> None:
            self.wfile.write((line + "\r\n").encode("utf-8"))

        def expect() -> str:
            return self.rfile.readline().decode("utf-8", errors="ignore").strip()

        profile = self.server.profile
        send(profile.get("banner", "+OK POP3 ready"))

        while True:
            try:
                line = expect()
                if not line:
                    break
                cmd = line.split()[0].upper()

                if cmd == "USER":
                    send(profile.get("USER", "+OK"))
                elif cmd == "PASS":
                    time.sleep(self.server.fail_delay)
                    send(profile.get("PASS", "-ERR invalid login"))
                elif cmd == "STAT":
                    send(profile.get("STAT", "+OK 0 0"))
                elif cmd == "LIST":
                    resp = profile.get("LIST", "+OK 0 messages")
                    for l in resp.split("\n"):
                        send(l)
                    if not resp.endswith("\n.") and resp.split("\n")[-1] != ".":
                        send(".")
                elif cmd == "RETR":
                    resp = profile.get("RETR", "+OK 0 octets")
                    for l in resp.split("\n"):
                        send(l)
                    if not resp.endswith("\n.") and resp.split("\n")[-1] != ".":
                        send(".")
                elif cmd == "DELE":
                    send(profile.get("DELE", "+OK"))
                elif cmd == "NOOP":
                    send(profile.get("NOOP", "+OK"))
                elif cmd == "RSET":
                    send(profile.get("RSET", "+OK"))
                elif cmd == "QUIT":
                    send(profile.get("QUIT", "+OK bye"))
                    break
                else:
                    key = line if line in profile else cmd
                    send(profile.get(key, "-ERR unrecognized command"))
            except Exception as exc:  # pragma: no cover - logging
                msg = "[pop3-honeypot] Error: {}".format(exc)
                syslog.syslog(syslog.LOG_ERR, msg)
                self.server.logger.error(msg)
                break


class POP3Server(socketserver.ThreadingTCPServer):
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
    parser = argparse.ArgumentParser(description="POP3 Honeypot Daemon")
    parser.add_argument("--host", default="0.0.0.0", help="Listen address")
    parser.add_argument("--port", type=int, default=110, help="Listen port")
    parser.add_argument("--config", default=DEFAULT_CONFIG, help="Path to POP3 profile JSON")
    parser.add_argument("--fail-delay", type=int, default=3, help="Delay in seconds after failed PASS")
    args = parser.parse_args(argv)

    logger = logging.getLogger("pop3-honeypot")
    logging.basicConfig(level=logging.INFO)

    profile = load_profile(args.config)

    server = POP3Server((args.host, args.port), POP3Handler, profile, args.fail_delay, logger)

    logger.info("Starting POP3 honeypot on %s:%s", args.host, args.port)
    syslog.openlog("pop3-honeypot")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
