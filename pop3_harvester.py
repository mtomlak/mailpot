import socket
import json
import time

POP3_HOST = "10.22.63.10"
POP3_PORT = 110

responses = {}

print(f"Connecting to {POP3_HOST}:{POP3_PORT}...")
with socket.create_connection((POP3_HOST, POP3_PORT), timeout=60) as sock:
    file = sock.makefile("rwb", buffering=0)

    def recv_line():
        line = file.readline().decode("utf-8", errors="ignore").strip()
        print(f"RECV: {line}")
        return line

    def recv_multiline():
        lines = []
        while True:
            line = recv_line()
            lines.append(line)
            if line == "." or line == "":
                break
        return "\n".join(lines)

    def send(cmd, multiline=False):
        print(f"SENT: {cmd}")
        file.write((cmd + "\r\n").encode("utf-8"))
        time.sleep(0.5)
        return recv_multiline() if multiline else recv_line()

    print("Getting banner...")
    responses["banner"] = recv_line()

    responses["USER"] = send("USER user")
    responses["PASS"] = send("PASS pass")
    responses["STAT"] = send("STAT")
    responses["LIST"] = send("LIST", multiline=True)
    responses["RETR"] = send("RETR 1", multiline=True)
    responses["DELE"] = send("DELE 1")
    responses["NOOP"] = send("NOOP")
    responses["RSET"] = send("RSET")
    responses["INVALID"] = send("FOOBAR")
    responses["QUIT"] = send("QUIT")

with open("/var/local/mailpot/pop3_profile.json", "w") as f:
    json.dump(responses, f, indent=2)

print("POP3 profile saved to pop3_profile.json")
