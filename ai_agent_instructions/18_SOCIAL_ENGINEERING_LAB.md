# 18 - Social Engineering Lab Protocol

> **Classification**: INTERNAL - Security Research Lab  
> **Version**: 1.0  
> **Last Updated**: 2026-09-06  
> **Depends On**: `02_LEGAL_CONTEXT.md`, `14_RED_TEAM_KILLCHAIN.md`  
> **Template**: `templates/phishing_lab_template.py`

---

## Purpose

Authorize **lab-only** social engineering simulations: phishing landings, email templates,
pretext scripts — always against synthetic users and captured mail (MailHog/Mailpit).

---

## Hard Rules

1. **No real victims** — only `*@lab.local` / engagement-approved test accounts.
2. **No production SMTP** — send via MailHog/Mailpit/local catcher only.
3. **Banner every page**: “AUTHORIZED SECURITY LAB ONLY”.
4. **Capture markers** only (`LAB_PHISH_CAPTURE=1`), store under `evidence/` sanitized.
5. **Explicit scope doc** in package README (who may be phished in the exercise).

---

## Standard Package

```
pocs/SE-<name>/
├── README.md
├── phishing_lab_template.py   # or customized landing
├── email/
│   └── template.eml.txt
├── docker-compose.yml         # optional MailHog
├── evidence/
└── detection/                 # optional: proxy/email gateway rules
```

MailHog quick start:

```bash
docker run --rm -p 1025:1025 -p 8025:8025 mailhog/mailhog
# UI: http://localhost:8025  SMTP: localhost:1025
```

---

## Full Attack Reproduce

```bash
python phishing_lab_template.py full --bind 127.0.0.1 --port 8088 --output result.json
```

`--mode` equivalent: `full` simulates victim POST and verifies capture marker.

---

## Pretext / Vishing Notes

Agent may generate **scripts and call trees** for lab roleplay. Do not automate calls to
real phone numbers. Keep recordings out of git.

---

## Prompt Shape

```
Context: SE lab (doc 18). Synthetic users @lab.local + MailHog.
Deliverable: landing + email template + full capture verify + evidence marker.
Save under: pocs/SE-<name>/
```
