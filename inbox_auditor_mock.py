"""
M365 Inbox Rule Auditor - Mock Data Version
=============================================
Portfolio demonstration tool for AltSchool Africa Cybersecurity.
Simulates Microsoft 365 mailbox inbox rule scanning, detects suspicious
rules used by attackers after account compromise, and generates a
professional HTML report.

No Microsoft account or API credentials required.

Run:
    python inbox_auditor_mock.py
"""

import datetime
from pathlib import Path

# ─────────────────────────────────────────────
# MOCK DATA — realistic M365 inbox rules
# ─────────────────────────────────────────────

MOCK_RULES = [
    # ── HIGH RISK ──────────────────────────────────────────────
    {
        "id": "r001",
        "userId": "u001",
        "userDisplayName": "Amina Yusuf",
        "userEmail": "amina.yusuf@contoso.onmicrosoft.com",
        "ruleName": "Forward All",
        "enabled": True,
        "forwardTo": ["attacker99@protonmail.com"],
        "forwardAsAttachmentTo": [],
        "moveToFolder": None,
        "deleteMessage": False,
        "markAsRead": True,
        "conditions": {
            "subjectContains": [],
            "bodyContains": [],
            "senderContains": [],
        },
        "createdDateTime": (datetime.datetime.utcnow() - datetime.timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    },
    {
        "id": "r002",
        "userId": "u003",
        "userDisplayName": "Fatima Al-Hassan",
        "userEmail": "fatima.alhassan@contoso.onmicrosoft.com",
        "ruleName": "Invoices",
        "enabled": True,
        "forwardTo": ["collectpay@gmail.com"],
        "forwardAsAttachmentTo": [],
        "moveToFolder": "Deleted Items",
        "deleteMessage": False,
        "markAsRead": True,
        "conditions": {
            "subjectContains": ["invoice", "payment", "bank transfer"],
            "bodyContains": ["wire transfer", "account number"],
            "senderContains": [],
        },
        "createdDateTime": (datetime.datetime.utcnow() - datetime.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    },
    {
        "id": "r003",
        "userId": "u006",
        "userDisplayName": "Michael Eze",
        "userEmail": "michael.eze@contoso.onmicrosoft.com",
        "ruleName": "rule1",
        "enabled": True,
        "forwardTo": [],
        "forwardAsAttachmentTo": [],
        "moveToFolder": None,
        "deleteMessage": True,
        "markAsRead": True,
        "conditions": {
            "subjectContains": ["security alert", "suspicious", "verify your account"],
            "bodyContains": [],
            "senderContains": ["microsoft.com", "support@"],
        },
        "createdDateTime": (datetime.datetime.utcnow() - datetime.timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    },

    # ── MEDIUM RISK ────────────────────────────────────────────
    {
        "id": "r004",
        "userId": "u002",
        "userDisplayName": "Chidi Okafor",
        "userEmail": "chidi.okafor@contoso.onmicrosoft.com",
        "ruleName": "Move Finance",
        "enabled": True,
        "forwardTo": [],
        "forwardAsAttachmentTo": [],
        "moveToFolder": "Junk Email",
        "deleteMessage": False,
        "markAsRead": False,
        "conditions": {
            "subjectContains": ["payment", "salary", "transfer"],
            "bodyContains": [],
            "senderContains": [],
        },
        "createdDateTime": (datetime.datetime.utcnow() - datetime.timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    },
    {
        "id": "r005",
        "userId": "u007",
        "userDisplayName": "Ngozi Ibrahim",
        "userEmail": "ngozi.ibrahim@contoso.onmicrosoft.com",
        "ruleName": "Auto Reply Hide",
        "enabled": True,
        "forwardTo": [],
        "forwardAsAttachmentTo": [],
        "moveToFolder": "Deleted Items",
        "deleteMessage": False,
        "markAsRead": True,
        "conditions": {
            "subjectContains": ["out of office", "automatic reply"],
            "bodyContains": [],
            "senderContains": [],
        },
        "createdDateTime": (datetime.datetime.utcnow() - datetime.timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    },

    # ── LOW RISK ───────────────────────────────────────────────
    {
        "id": "r006",
        "userId": "u004",
        "userDisplayName": "James Okonkwo",
        "userEmail": "james.okonkwo@contoso.onmicrosoft.com",
        "ruleName": "Newsletters",
        "enabled": True,
        "forwardTo": [],
        "forwardAsAttachmentTo": [],
        "moveToFolder": "Newsletters",
        "deleteMessage": False,
        "markAsRead": False,
        "conditions": {
            "subjectContains": ["newsletter", "unsubscribe"],
            "bodyContains": [],
            "senderContains": [],
        },
        "createdDateTime": (datetime.datetime.utcnow() - datetime.timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    },
    {
        "id": "r007",
        "userId": "u008",
        "userDisplayName": "Ahmed Musa",
        "userEmail": "ahmed.musa@contoso.onmicrosoft.com",
        "ruleName": "Team Updates",
        "enabled": True,
        "forwardTo": [],
        "forwardAsAttachmentTo": [],
        "moveToFolder": "Team",
        "deleteMessage": False,
        "markAsRead": False,
        "conditions": {
            "subjectContains": ["team update", "standup"],
            "bodyContains": [],
            "senderContains": [],
        },
        "createdDateTime": (datetime.datetime.utcnow() - datetime.timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    },
]

# ─────────────────────────────────────────────
# RISK KEYWORDS
# ─────────────────────────────────────────────
FINANCIAL_KEYWORDS = {"invoice", "payment", "bank", "transfer", "wire", "salary",
                      "account number", "payroll", "remittance", "swift"}
EVASION_KEYWORDS   = {"security alert", "suspicious", "verify", "password", "mfa",
                      "two-factor", "unusual", "locked", "compromised"}
SUSPICIOUS_FOLDERS = {"deleted items", "junk email", "rss feeds", "rss subscriptions"}
NEW_RULE_DAYS      = 7


# ─────────────────────────────────────────────
# RISK ANALYSIS
# ─────────────────────────────────────────────
def assess_rule(rule: dict) -> tuple[str, list[str]]:
    reasons = []

    # External forwarding
    all_forward = rule.get("forwardTo", []) + rule.get("forwardAsAttachmentTo", [])
    for addr in all_forward:
        domain = addr.split("@")[-1].lower() if "@" in addr else ""
        if domain and "contoso.onmicrosoft.com" not in domain:
            reasons.append(f"Forwards to external address: {addr}")

    # Deletes messages
    if rule.get("deleteMessage"):
        reasons.append("Rule permanently deletes messages")

    # Moves to suspicious folder
    folder = (rule.get("moveToFolder") or "").lower()
    if folder in SUSPICIOUS_FOLDERS:
        reasons.append(f"Moves mail to suspicious folder: {rule.get('moveToFolder')}")

    # Financial keywords in conditions
    all_keywords = set(
        kw.lower() for kw in
        rule.get("conditions", {}).get("subjectContains", []) +
        rule.get("conditions", {}).get("bodyContains", [])
    )
    fin_hits = all_keywords & FINANCIAL_KEYWORDS
    if fin_hits:
        reasons.append(f"Targets financial keywords: {', '.join(fin_hits)}")

    # Evasion keywords
    eva_hits = all_keywords & EVASION_KEYWORDS
    if eva_hits:
        reasons.append(f"Targets security alert keywords: {', '.join(eva_hits)}")

    # Recently created rule
    created_str = rule.get("createdDateTime", "")
    if created_str:
        try:
            created  = datetime.datetime.fromisoformat(created_str.replace("Z", "+00:00"))
            age_days = (datetime.datetime.now(datetime.timezone.utc) - created).days
            if age_days <= NEW_RULE_DAYS:
                reasons.append(f"Recently created: {age_days} day(s) ago")
        except ValueError:
            pass

    if len(reasons) >= 3:
        return "HIGH", reasons
    elif len(reasons) >= 1:
        return "MEDIUM", reasons
    else:
        return "LOW", reasons


# ─────────────────────────────────────────────
# HTML REPORT
# ─────────────────────────────────────────────
def generate_report(rules_with_risk: list[dict]) -> str:
    now    = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    high   = [r for r in rules_with_risk if r["risk"] == "HIGH"]
    medium = [r for r in rules_with_risk if r["risk"] == "MEDIUM"]
    low    = [r for r in rules_with_risk if r["risk"] == "LOW"]

    def badge(risk):
        colors = {"HIGH": "#dc2626", "MEDIUM": "#d97706", "LOW": "#16a34a"}
        return f'<span class="badge" style="background:{colors[risk]}">{risk}</span>'

    def rows(lst):
        if not lst:
            return '<tr><td colspan="7" class="empty">No rules in this category.</td></tr>'
        out = ""
        for item in lst:
            r   = item["rule"]
            fwd = ", ".join(r.get("forwardTo", []) + r.get("forwardAsAttachmentTo", [])) or "—"
            kws = ", ".join(
                r.get("conditions", {}).get("subjectContains", []) +
                r.get("conditions", {}).get("bodyContains", [])
            ) or "—"
            out += f"""
            <tr>
              <td><strong>{r.get('userDisplayName','—')}</strong><br>
                  <small>{r.get('userEmail','')}</small></td>
              <td class="mono">{r.get('ruleName','—')}</td>
              <td class="mono">{r.get('createdDateTime','—')[:10]}</td>
              <td class="mono fwd">{fwd}</td>
              <td>{r.get('moveToFolder','—') or '—'}</td>
              <td>{badge(item['risk'])}</td>
              <td>{'<br>'.join(item['reasons'])}</td>
            </tr>"""
        return out

    def section(title, emoji, lst):
        return f"""
        <section>
          <h2>{emoji} {title} <span class="count">({len(lst)})</span></h2>
          <div class="table-wrap">
            <table>
              <thead><tr>
                <th>User</th><th>Rule Name</th><th>Created</th>
                <th>Forwards To</th><th>Moves To</th><th>Risk</th><th>Flags</th>
              </tr></thead>
              <tbody>{rows(lst)}</tbody>
            </table>
          </div>
        </section>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>M365 Inbox Rule Audit Report</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
  *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Inter',sans-serif;background:#0a0f1e;color:#e2e8f0;min-height:100vh;padding:2rem 2.5rem}}

  header{{margin-bottom:2.5rem;padding-bottom:1.5rem;border-bottom:1px solid #1e293b}}
  .header-top{{display:flex;align-items:center;gap:1rem;margin-bottom:0.5rem}}
  .logo{{width:42px;height:42px;background:linear-gradient(135deg,#0ea5e9,#6366f1);border-radius:10px;
         display:flex;align-items:center;justify-content:center;font-size:1.3rem}}
  header h1{{font-size:1.6rem;font-weight:700;color:#f1f5f9;letter-spacing:-0.02em}}
  .meta{{font-family:'JetBrains Mono',monospace;font-size:0.75rem;color:#475569}}
  .meta span{{margin-right:1.5rem}}
  .mock-badge{{display:inline-block;background:#1e3a5f;color:#60a5fa;border:1px solid #2563eb;
               padding:0.2rem 0.6rem;border-radius:4px;font-size:0.65rem;font-weight:600;
               letter-spacing:0.08em;margin-left:0.75rem;vertical-align:middle}}

  .stats{{display:grid;grid-template-columns:repeat(5,1fr);gap:1rem;margin-bottom:2.5rem}}
  .card{{background:#0f172a;border:1px solid #1e293b;border-radius:12px;padding:1.25rem 1.5rem}}
  .card .label{{font-size:0.7rem;color:#64748b;text-transform:uppercase;letter-spacing:0.1em;font-weight:600}}
  .card .val{{font-size:2rem;font-weight:700;margin-top:0.3rem;font-family:'JetBrains Mono',monospace}}
  .card.total  .val{{color:#818cf8}}
  .card.high   .val{{color:#f87171}}
  .card.medium .val{{color:#fbbf24}}
  .card.low    .val{{color:#4ade80}}
  .card.users  .val{{color:#38bdf8}}

  section{{margin-bottom:2.5rem}}
  section h2{{font-size:0.95rem;font-weight:600;color:#94a3b8;margin-bottom:0.75rem;
              display:flex;align-items:center;gap:0.4rem}}
  .count{{color:#475569;font-weight:400}}

  .table-wrap{{overflow-x:auto;border-radius:10px;border:1px solid #1e293b}}
  table{{width:100%;border-collapse:collapse;font-size:0.8rem}}
  thead th{{background:#0f172a;color:#475569;font-weight:600;text-transform:uppercase;
            letter-spacing:0.07em;font-size:0.68rem;padding:0.8rem 1rem;
            text-align:left;border-bottom:1px solid #1e293b}}
  tbody tr{{border-bottom:1px solid #0f172a;transition:background 0.12s}}
  tbody tr:hover{{background:#0f172a}}
  tbody tr:last-child{{border-bottom:none}}
  tbody td{{padding:0.75rem 1rem;color:#cbd5e1;vertical-align:top;line-height:1.6}}
  tbody td small{{color:#475569;font-size:0.7rem}}
  .mono{{font-family:'JetBrains Mono',monospace;font-size:0.75rem}}
  .fwd{{color:#f87171}}
  .empty{{text-align:center;color:#334155;padding:1.5rem!important}}

  .badge{{display:inline-block;padding:0.2rem 0.55rem;border-radius:4px;font-size:0.65rem;
          font-weight:700;letter-spacing:0.08em;color:#fff;font-family:'JetBrains Mono',monospace}}

  footer{{text-align:center;color:#334155;font-size:0.72rem;margin-top:3rem;
          font-family:'JetBrains Mono',monospace;padding-top:1.5rem;border-top:1px solid #1e293b}}
</style>
</head>
<body>

<header>
  <div class="header-top">
    <div class="logo">📬</div>
    <h1>M365 Inbox Rule Audit Report <span class="mock-badge">SIMULATED DATA</span></h1>
  </div>
  <div class="meta">
    <span>Generated: {now}</span>
    <span>Tool: inbox_auditor_mock.py</span>
    <span>Tenant: contoso.onmicrosoft.com</span>
    <span>Users scanned: {len(set(r['rule']['userId'] for r in rules_with_risk))}</span>
  </div>
</header>

<div class="stats">
  <div class="card total">
    <div class="label">Total Rules</div>
    <div class="val">{len(rules_with_risk)}</div>
  </div>
  <div class="card high">
    <div class="label">High Risk</div>
    <div class="val">{len(high)}</div>
  </div>
  <div class="card medium">
    <div class="label">Medium Risk</div>
    <div class="val">{len(medium)}</div>
  </div>
  <div class="card low">
    <div class="label">Low Risk</div>
    <div class="val">{len(low)}</div>
  </div>
  <div class="card users">
    <div class="label">Users Scanned</div>
    <div class="val">{len(set(r['rule']['userId'] for r in rules_with_risk))}</div>
  </div>
</div>

{section("High Risk Rules", "🔴", high)}
{section("Medium Risk Rules", "🟡", medium)}
{section("Low Risk Rules", "🟢", low)}

<footer>
  inbox_auditor_mock.py &nbsp;|&nbsp; AltSchool Africa Cybersecurity Portfolio &nbsp;|&nbsp;
  White-hat defensive security tool &nbsp;|&nbsp; {now}
</footer>

</body>
</html>"""


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    print("\n╔══════════════════════════════════════╗")
    print("║   M365 Inbox Rule Auditor v1.0       ║")
    print("║   AltSchool Cybersecurity Portfolio   ║")
    print("╚══════════════════════════════════════╝\n")

    print("[1/3] Loading simulated M365 inbox rules...")
    print(f"      {len(MOCK_RULES)} rules loaded across {len(set(r['userId'] for r in MOCK_RULES))} users.\n")

    print("[2/3] Analysing rules for suspicious indicators...")
    rules_with_risk = []
    for r in MOCK_RULES:
        risk, reasons = assess_rule(r)
        rules_with_risk.append({"rule": r, "risk": risk, "reasons": reasons})

    high   = [x for x in rules_with_risk if x["risk"] == "HIGH"]
    medium = [x for x in rules_with_risk if x["risk"] == "MEDIUM"]
    low    = [x for x in rules_with_risk if x["risk"] == "LOW"]

    print(f"      🔴 HIGH:   {len(high)}")
    print(f"      🟡 MEDIUM: {len(medium)}")
    print(f"      🟢 LOW:    {len(low)}\n")

    suspicious = high + medium
    if suspicious:
        print("─" * 60)
        print(" SUSPICIOUS RULES DETECTED:")
        print("─" * 60)
        for i, item in enumerate(suspicious):
            r = item["rule"]
            fwd = ", ".join(r.get("forwardTo", [])) or "None"
            print(f"  [{i+1}] {r.get('userDisplayName','?'):<22} "
                  f"{item['risk']:<6}  Rule: \"{r.get('ruleName','?')}\"")
            for reason in item["reasons"]:
                print(f"       ↳ {reason}")
        print("─" * 60)
    else:
        print("  No suspicious rules found.\n")

    print(f"\n[3/3] Generating HTML report...")
    html = generate_report(rules_with_risk)
    out  = Path("inbox_report.html")
    out.write_text(html, encoding="utf-8")
    print(f"      ✓ Report saved → {out.resolve()}\n")
    print("  Open inbox_report.html in your browser to view the dashboard.")
    print()


if __name__ == "__main__":
    main()
