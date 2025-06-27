# Mailpot

This repository contains a simple SMTP honeypot implementation in `servers/smtp.py`.

The honeypot mimics an SMTP server by reading command responses from a JSON
profile. By default it looks for `/var/local/mailpot/smtp_profile.json`, but you
can supply a different path with `--config`.


Clone this repository into `/var/local/mailpot` so the default paths work.
The layout should be:

```
/var/local/mailpot/
  servers/
    smtp.py
    imap.py
  smtp_harvester.py
  imap_harvester.py
  pop3_harvester.py
  smtp_profile.json
  imap_profile.json
```

## Running

```bash
python3 servers/smtp.py --host 0.0.0.0 --port 2525 --config smtp_profile.json
```

A sample JSON profile is provided below for convenience.

```json
{
  "banner": "220 smtp.mx.profiweb.biz Cisco NetWorks ESMTP server",
  "HELO test.local": "250 smtp.mx.profiweb.biz",
  "EHLO test.local": "250-smtp.mx.profiweb.biz\n250-PIPELINING\n250-SIZE 1073741824\n250-VRFY\n250-ETRN\n250-STARTTLS\n250-AUTH PLAIN LOGIN\n250-ENHANCEDSTATUSCODES\n250-8BITMIME\n250 DSN",
  "MAIL FROM": "250 2.1.0 Ok",
  "RCPT TO": "250 2.1.5 Ok",
  "DATA": "354 End data with <CR><LF>.<CR><LF>",
  "DATA body": "250 2.0.0 Ok: queued as 4bRTPw0h6lz1N7HN136e6d94",
  "QUIT": ""
}
```

## IMAP honeypot

`servers/imap.py` implements a minimal IMAP server that behaves similarly to the
SMTP honeypot. It reads its responses from `/var/local/mailpot/imap_profile.json`
unless a different file is provided with `--config`.

```bash
python3 servers/imap.py --host 0.0.0.0 --port 1143 --config imap_profile.json
```

The IMAP profile supports custom responses for standard commands. In addition to
`LOGIN` and `LOGOUT`, the handler understands the `STARTTLS`, `AUTHENTICATE`, and
`NOOP` commands, returning the strings configured in the profile.

