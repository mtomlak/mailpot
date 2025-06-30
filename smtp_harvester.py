import socket
import base64
import json
import time

SMTP_HOST = "10.22.63.10"
SMTP_PORT = 25

responses = {}

print("Connecting to {}:{}...".format(SMTP_HOST, SMTP_PORT))
with socket.create_connection((SMTP_HOST, SMTP_PORT), timeout=60) as sock:
    file = sock.makefile("rwb", buffering=0)

    def recv_response():
        lines = []
        while True:
            line = file.readline().decode("utf-8", errors="ignore").strip()
            print("RECV: {}".format(line))
            lines.append(line)
            if not line[:3].isdigit() or not line[3:4] == "-":
                break
        return "\n".join(lines)

    def send(cmd):
        print("SENT: {}".format(cmd))
        file.write((cmd + "\r\n").encode("utf-8"))
        time.sleep(0.5)
        return recv_response()

    print("Getting banner...")
    responses["banner"] = recv_response()

    # EHLO responses are often multi-line and contain server capabilities.
    resp_ehlo = send("EHLO test.local")
    responses["EHLO test.local"] = resp_ehlo
    responses["AUTH PLAIN"] = send("AUTH PLAIN {}".format(base64.b64encode(b"\0user\0pass").decode()))
    responses["AUTH LOGIN"] = send("AUTH LOGIN")
    responses["AUTH LOGIN user"] = send(base64.b64encode(b"user").decode())
    responses["AUTH LOGIN pass"] = send(base64.b64encode(b"pass").decode())
    responses["HELO test.local"] = send("HELO test.local")
    responses["MAIL FROM"] = send("MAIL FROM:<test@example.com>")
    responses["RCPT TO"] = send("RCPT TO:<admin@example.com>")
    responses["DATA"] = send("DATA")
    responses["DATA body"] = send("Subject: test\r\n\r\nHello.\r\n.")
    responses["VRFY"] = send("VRFY root")
    responses["ETRN"] = send("ETRN somehost")
    responses["STARTTLS"] = send("STARTTLS")
    responses["INVALID"] = send("FOOBAR")
    responses["QUIT"] = send("QUIT")

with open("/var/local/mailpot/smtp_profile.json", "w") as f:
    json.dump(responses, f, indent=2)

print("SMTP profile saved to smtp_profile.json")
