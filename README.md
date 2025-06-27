# Mailpot

This repository contains a simple SMTP honeypot implementation in `mailpot/smtp.py`.

The honeypot mimics an SMTP server by reading command responses from a JSON
profile. By default it looks for `/var/local/mailpot/smtp_profile.json`, but you
can supply a different path with `--config`.

## Running

```bash
python3 -m mailpot.smtp --host 0.0.0.0 --port 2525 --config sample_profile.json
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

