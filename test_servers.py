import argparse
import socket
import subprocess
import sys
import time


ROOT = __file__.rsplit('/', 1)[0]


def run_server(module: str, port: int, config: str):
    """Launch a honeypot server as a subprocess."""
    return subprocess.Popen([
        sys.executable,
        f"{ROOT}/servers/{module}.py",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--config",
        f"{ROOT}/{config}",
    ])


def stop_server(proc: subprocess.Popen):
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()


def test_smtp():
    port = 2525
    proc = run_server("smtp", port, "smtp_profile.json")
    try:
        time.sleep(1)
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            file = sock.makefile("rwb", buffering=0)
            banner = file.readline().decode().strip()
            if not banner.startswith("220"):
                raise RuntimeError(f"unexpected banner: {banner}")
            file.write(b"HELO test.local\r\n")
            resp = file.readline().decode().strip()
            if not resp.startswith("250"):
                raise RuntimeError(f"unexpected HELO response: {resp}")
            file.write(b"QUIT\r\n")
            file.readline()
    finally:
        stop_server(proc)


def test_pop3():
    port = 8110
    proc = run_server("pop3", port, "pop3_profile.json")
    try:
        time.sleep(1)
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            file = sock.makefile("rwb", buffering=0)
            banner = file.readline().decode().strip()
            if not banner.startswith("+OK"):
                raise RuntimeError(f"unexpected banner: {banner}")
            file.write(b"QUIT\r\n")
            resp = file.readline().decode().strip()
            if not resp.startswith("+OK"):
                raise RuntimeError(f"unexpected QUIT response: {resp}")
    finally:
        stop_server(proc)


def test_imap():
    port = 8143
    proc = run_server("imap", port, "imap_profile.json")
    try:
        time.sleep(1)
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            file = sock.makefile("rwb", buffering=0)
            banner = file.readline().decode().strip()
            if not banner.startswith("* "):
                raise RuntimeError(f"unexpected banner: {banner}")
            file.write(b"a1 NOOP\r\n")
            resp = file.readline().decode().strip()
            if not resp.startswith("a1 "):
                raise RuntimeError(f"unexpected NOOP response: {resp}")
            file.write(b"a2 LOGOUT\r\n")
            bye = file.readline().decode().strip()
            if not bye.startswith("* BYE"):
                raise RuntimeError(f"unexpected BYE response: {bye}")
            logout = file.readline().decode().strip()
            if not logout.startswith("a2 "):
                raise RuntimeError(f"unexpected LOGOUT response: {logout}")
    finally:
        stop_server(proc)


TESTS = {
    "smtp": test_smtp,
    "pop3": test_pop3,
    "imap": test_imap,
}


def main():
    parser = argparse.ArgumentParser(description="Test honeypot servers")
    parser.add_argument(
        "--server",
        choices=list(TESTS.keys()),
        help="Only run tests for the specified server",
    )
    args = parser.parse_args()

    names = [args.server] if args.server else list(TESTS.keys())
    success = True
    for name in names:
        print(f"{name} ... ", end="", flush=True)
        try:
            TESTS[name]()
            print("ok")
        except Exception as exc:
            success = False
            print(f"ERROR: {exc}")
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
