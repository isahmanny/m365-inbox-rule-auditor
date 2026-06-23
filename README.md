# M365 Inbox Rule Auditor

A white-hat Python security tool that scans Microsoft 365 mailboxes 
for suspicious inbox rules used by attackers after account compromise.

## What It Detects
- External email forwarding (data exfiltration)
- Rules targeting financial keywords (invoice, payment, transfer)
- Rules that permanently delete messages (covering tracks)
- Rules moving mail to Junk/Deleted Items (hiding replies)
- Rules targeting security alert keywords (blocking MFA notifications)
- Recently created rules on established accounts

## Risk Scoring
| Level | Triggers |
|-------|----------|
| HIGH | 3+ indicators |
| MEDIUM | 1–2 indicators |
| LOW | No indicators |

## Tools Used
- Python 3.12
- Microsoft Graph API (architecture)
- HTML/CSS Dashboard

## Project Context
Built as part of AltSchool Africa Cybersecurity programme.
Covers: BEC detection, inbox persistence, SOC monitoring.
