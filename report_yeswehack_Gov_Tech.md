# Subdomain Takeover via Dangling CNAME to Expiring Third-Party Domain (nparks.gov.sg)

## Title (for YesWeHack)
Subdomain Takeover Risk: 3 nparks.gov.sg subdomains point to unresolvable third-party domain expiring Dec 2026

## Severity
High

## Asset
nparks.gov.sg — National Parks Board (*.gov.sg scope)

## Vulnerability Type
CWE-672 — Operation on a Resource after Expiration or Release
Subdomain Takeover

---

## Summary

Three subdomains of **nparks.gov.sg** have DNS CNAME records pointing to subdomains of the third-party domain **hipster-virtual.com** that no longer resolve. The CNAME targets have no A records, making the chain broken.

**The critical factor:** `hipster-virtual.com` is registered through GoDaddy and **expires on 2026-12-07** — approximately **69 days from now**. If the current registrant does not renew it, anyone can register this domain for ~$12 and immediately serve arbitrary content on three Singapore government subdomains.

---

## Affected Assets

| Government Subdomain | CNAME Target | Resolves? |
|---|---|---|
| `near.nparks.gov.sg` | `nparks-frontend-live.hipster-virtual.com` | No |
| `admin-near.nparks.gov.sg` | `nparks-backend-live.hipster-virtual.com` | No |
| `api-near.nparks.gov.sg` | `nparks-api-live.hipster-virtual.com` | No |

---

## Steps to Reproduce

**Step 1** — Verify the CNAME records exist:

```bash
dig CNAME near.nparks.gov.sg +short
# Output: nparks-frontend-live.hipster-virtual.com.

dig CNAME admin-near.nparks.gov.sg +short
# Output: nparks-backend-live.hipster-virtual.com.

dig CNAME api-near.nparks.gov.sg +short
# Output: nparks-api-live.hipster-virtual.com.
```

**Step 2** — Verify the CNAME targets do NOT resolve (no A record):

```bash
dig A nparks-frontend-live.hipster-virtual.com +short
# Output: (empty — no A record)

dig A nparks-backend-live.hipster-virtual.com +short
# Output: (empty — no A record)

dig A nparks-api-live.hipster-virtual.com +short
# Output: (empty — no A record)
```

**Step 3** — Verify the parent domain resolves but the subdomains do not:

```bash
dig A hipster-virtual.com +short
# Output: 54.254.125.227 / 52.220.168.176 / 47.131.185.82
# (AWS ap-southeast-1 — the domain is alive, but NParks' subdomains on it are gone)
```

**Step 4** — Verify the domain expiration date:

```bash
whois hipster-virtual.com | grep -i expir
# Output: Registry Expiry Date: 2026-12-07T01:25:40Z
```

The domain is registered through **GoDaddy.com, LLC** and uses **AWS Route 53** name servers.

---

## Attack Scenario

### Immediate path (if hipster-virtual.com allows subdomain registration)
If `hipster-virtual.com` is a hosting platform that allows customers to create subdomains, an attacker could sign up, create `nparks-frontend-live`, `nparks-backend-live`, and `nparks-api-live`, and the government CNAME records would immediately route traffic to the attacker's servers.

### Near-term path (domain expiration — 69 days)
1. Wait for `hipster-virtual.com` to expire on **2026-12-07**
2. Register the domain (~$12 on any registrar)
3. Set up DNS with A records for the three NParks subdomains
4. Serve arbitrary content on `near.nparks.gov.sg`, `admin-near.nparks.gov.sg`, and `api-near.nparks.gov.sg`

No interaction with NParks' infrastructure is needed. The attacker controls the DNS resolution through the third-party domain.

---

## Impact

**Phishing under .gov.sg trust:**
An attacker could host a convincing government login page at `near.nparks.gov.sg`. The `.gov.sg` TLD carries strong implicit trust — browsers show no warning, corporate firewalls whitelist it, and users have no reason to suspect the content is malicious. This could be used to harvest credentials for Singpass, NParks services, or any government portal.

**Cookie exposure:**
If `nparks.gov.sg` sets cookies scoped to the parent domain (`Domain=.nparks.gov.sg`) or if any application shares cookies across subdomains, the attacker-controlled subdomain could read those cookies, potentially hijacking authenticated sessions.

**Malware distribution:**
Hosting malware downloads under a `.gov.sg` domain bypasses most URL reputation filters, email security gateways, and corporate web proxies that whitelist government domains.

**Supply chain risk:**
The subdomain names (`admin-near`, `api-near`, `near`) suggest these were application components (frontend, backend, API). If any internal system still references these hostnames (monitoring, CI/CD, scripts), the attacker could intercept that traffic.

---

## Evidence Summary

| Item | Value |
|------|-------|
| Affected subdomains | `near.nparks.gov.sg`, `admin-near.nparks.gov.sg`, `api-near.nparks.gov.sg` |
| CNAME targets | `nparks-{frontend,backend,api}-live.hipster-virtual.com` |
| Target A records | **None** — broken CNAME chain |
| Third-party domain registrar | GoDaddy.com, LLC |
| Third-party domain expiry | **2026-12-07T01:25:40Z** (69 days) |
| Third-party DNS | AWS Route 53 |
| Third-party hosting region | AWS ap-southeast-1 (Singapore) |
| Discovery method | Passive DNS enumeration + CNAME resolution verification |
| Date discovered | 2026-09-29 |

---

## Remediation

**Immediate (< 1 day):** Remove the three stale CNAME records from the `nparks.gov.sg` DNS zone. Since the target service is decommissioned, these records serve no purpose and only create risk.

**Short-term:** Audit all `*.gov.sg` DNS zones for other CNAME records pointing to third-party domains, and verify that each target is still active and under government control.

**Long-term:** Implement a DNS hygiene process that includes removing CNAME records when decommissioning services hosted on third-party platforms. Consider monitoring CNAME targets for expiration dates.

---

## Notes

- I did **not** attempt to register the domain or any subdomains. This report is based purely on passive DNS analysis.
- All evidence is independently verifiable using standard DNS tools (`dig`, `whois`).
- The subdomain naming pattern (`frontend-live`, `backend-live`, `api-live`) suggests a decommissioned web application that was previously hosted on `hipster-virtual.com`.
