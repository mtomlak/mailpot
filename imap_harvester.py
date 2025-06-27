import socket
import json
import time

IMAP_HOST = "10.22.63.10"
IMAP_PORT = 143

responses = {}

print(f"Connecting to {IMAP_HOST}:{IMAP_PORT}...")
with socket.create_connection((IMAP_HOST, IMAP_PORT), timeout=60) as sock:
    file = sock.makefile("rwb", buffering=0)

    def recv_line():
        line = file.readline().decode("utf-8", errors="ignore").strip()
        print(f"RECV: {line}")
        return line

    def send(tag, cmd):
        full = f"{tag} {cmd}"
        print(f"SENT: {full}")
        file.write((full + "\r\n").encode("utf-8"))
        time.sleep(0.5)
        return recv_line()

    print("Getting banner...")
    responses["banner"] = recv_line()

    responses["LOGIN"] = send("a1", "LOGIN user pass")
    responses["STARTTLS"] = send("a2", "STARTTLS")
    responses["AUTHENTICATE"] = send("a3", "AUTHENTICATE PLAIN")
    responses["NOOP"] = send("a4", "NOOP")
    responses["INVALID"] = send("a5", "FOOBAR")

    print("Sending LOGOUT...")
    file.write(b"a6 LOGOUT\r\n")
    responses["BYE"] = recv_line()
    responses["LOGOUT"] = recv_line()

with open("/var/local/mailpot/imap_profile.json", "w") as f:
    json.dump(responses, f, indent=2)

print("IMAP profile saved to imap_profile.json")
