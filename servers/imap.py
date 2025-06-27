#!/usr/bin/env python3
"""Simple IMAP honeypot server."""

import argparse
import json
import logging
import socketserver
import sys
import syslog
import time

DEFAULT_CONFIG = "/var/local/mailpot/imap_profile.json"


class IMAPHandler(socketserver.StreamRequestHandler):
    """Handle IMAP interactions based on a JSON profile."""

    def handle(self) -> None:
        peer = self.connection.getpeername()
        syslog.syslog(syslog.LOG_INFO, f"[imap-honeypot] Connection from {peer[0]}:{peer[1]}")
        self.server.logger.info("Connection from %s:%s", peer[0], peer[1])

        def send(line: str) -> None:
            self.wfile.write((line + "\r\n").encode("utf-8"))

        def expect() -> str:
            return self.rfile.readline().decode("utf-8", errors="ignore").strip()

        profile = self.server.profile
        banner = profile.get("banner", "OK IMAP4rev1 Service Ready")
        send(f"* {banner}")

        while True:
            try:
                line = expect()
                if not line:
                    break
                parts = line.split()
                if not parts:
                    continue
                tag = parts[0]
                cmd = parts[1].upper() if len(parts) > 1 else ""

                if cmd == "LOGIN":
                    time.sleep(self.server.fail_delay)
                    resp = profile.get("LOGIN", "NO LOGIN failed")
                    send(f"{tag} {resp}")
                elif cmd == "STARTTLS":
                    resp = profile.get("STARTTLS", "OK Begin TLS negotiation now")
                    send(f"{tag} {resp}")
                elif cmd == "AUTHENTICATE":
                    time.sleep(self.server.fail_delay)
                    resp = profile.get("AUTHENTICATE", "NO AUTHENTICATE not supported")
                    send(f"{tag} {resp}")
                elif cmd == "NOOP":
                    resp = profile.get("NOOP", "OK NOOP completed")
                    send(f"{tag} {resp}")
                elif cmd == "LOGOUT":
                    resp = profile.get("LOGOUT", "OK LOGOUT completed")
                    bye = profile.get("BYE", "BYE Logging out")
                    send(f"* {bye}")
                    send(f"{tag} {resp}")
                    break
                else:
                    key = line if line in profile else cmd
                    resp = profile.get(key, "BAD Command not recognized")
                    send(f"{tag} {resp}")
            except Exception as exc:  # pragma: no cover - logging
                msg = f"[imap-honeypot] Error: {exc}"
                syslog.syslog(syslog.LOG_ERR, msg)
                self.server.logger.error(msg)
                break


class IMAPServer(socketserver.ThreadingTCPServer):
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
    parser = argparse.ArgumentParser(description="IMAP Honeypot Daemon")
    parser.add_argument("--host", default="0.0.0.0", help="Listen address")
    parser.add_argument("--port", type=int, default=143, help="Listen port")
    parser.add_argument("--config", default=DEFAULT_CONFIG, help="Path to IMAP profile JSON")
    parser.add_argument("--fail-delay", type=int, default=3, help="Delay in seconds after failed LOGIN")
    args = parser.parse_args(argv)

    logger = logging.getLogger("imap-honeypot")
    logging.basicConfig(level=logging.INFO)

    profile = load_profile(args.config)

    server = IMAPServer((args.host, args.port), IMAPHandler, profile, args.fail_delay, logger)

    logger.info("Starting IMAP honeypot on %s:%s", args.host, args.port)
    syslog.openlog("imap-honeypot")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
