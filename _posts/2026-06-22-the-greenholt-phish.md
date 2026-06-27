---
title: "TryHackMe — The Greenholt Phish"
date: 2026-06-22
categories: [TryHackMe, SOC Level 1]
tags: [phishing, email-analysis, email-headers, spf, dmarc, virustotal, blue-team, bec]
---

## Overview

| | |
|---|---|
| **Room** | The Greenholt Phish |
| **Path** | SOC Level 1 |
| **Difficulty** | Easy |
| **Tools** | Mozilla Thunderbird · dmarcian · IPinfo · VirusTotal · `sha256sum` |

The scenario: a suspicious email has been flagged and escalated to the SOC for investigation. The objective is to perform a structured analysis of the email — examining headers, sender metadata, DNS authentication records, the originating IP, and the attached file — to determine whether the email is malicious and to extract key indicators of compromise (IOCs).

---

## Opening the email

The challenge file `challenge.eml` is opened in **Mozilla Thunderbird**. At first glance, the email presents itself as a routine financial notification, referencing an interbank SWIFT transfer. The body includes transaction details and claims that a payment receipt is attached.

![Full email view in Thunderbird](/assets/img/posts/greenholt-phish/01-thunderbird-email.png)

Nothing in the visible email body immediately reveals malicious intent — which is precisely the point. The analysis begins at the header level.

---

## Header analysis

The first four questions are answered entirely through email header inspection — no additional tools required at this stage.

---

### Q1 — What is the Transfer Reference Number listed in the Subject line?
**Answer:** `09674321`

![Subject line highlighted — Transfer Reference Number](/assets/img/posts/greenholt-phish/Screenshot_1.png)

The subject line reads: `webmaster@redacted.org your: Transfer Reference Number:(09674321)`. The reference number is embedded in both the subject and the email body, lending the message an air of legitimacy.

---

### Q2 — What is the display name of the sender?
**Answer:** `Mr. James Jackson`

![Display name highlighted in Thunderbird header](/assets/img/posts/greenholt-phish/Screenshot_2.png)

The sender's display name is `Mr. James Jackson`. Display names are entirely attacker-controlled and carry no authentication weight — they are trivial to spoof.

---

### Q3 — What is the sender's email address?
**Answer:** `info@mutawamarine.com`

![Sender email address highlighted](/assets/img/posts/greenholt-phish/Screenshot_3.png)

The `From` field shows `info@mutawamarine.com`. While this is a real domain, its presence here does not confirm legitimacy — email `From` fields can be spoofed independently of the actual sending infrastructure.

---

### Q4 — What email address will receive a reply to this email?
**Answer:** `info.mutawamarine@mail.com`

![Reply-To address highlighted](/assets/img/posts/greenholt-phish/Screenshot_4.png)

> **Red flag #1 — Reply-To mismatch.** The `Reply-To` header is set to `info.mutawamarine@mail.com` — a generic free-mail address, completely separate from the sender's domain. Any victim who replies will be sending their response directly to an attacker-controlled inbox. This is a textbook **Business Email Compromise (BEC)** tactic.

---

## Message source analysis

Moving beyond the visible header, the raw message source is examined via **View → Message Source** in Thunderbird. This exposes the full SMTP routing chain and authentication results.

---

### Q5 — What is the originating IP address of this email?
**Answer:** `192.119.71.157`

![Raw message source showing originating IP in Received header](/assets/img/posts/greenholt-phish/Screenshot_5.png)

There is no `X-Originating-IP` header exposed in this message. Instead, the originating IP is traced by reading the `Received` chain from bottom to top. The relevant entry is:

```
Received: from hwsrv-737338.hostwindsdns.com ([192.119.71.157]:51810
    helo=mutawamarine
    by sub.redacted.com with esmtp (Exim 4.80)
    (envelope-from <info@mutawamarine.com>)
    id 1jissD-0004g5-Ts
```

The `helo=mutawamarine` value is notable — the sending server is identifying itself as `mutawamarine`, further reinforcing the impersonation. The actual IP is `192.119.71.157`.

Also visible in the source is confirmation that **SPF failed**:

```
Received-SPF: fail (domain of mutawamarine.com does not designate x.x.x.x as permitted sender)
```

This is a critical signal that the email did not originate from infrastructure authorized by the domain owner.

---

## IP investigation

### Q6 — Who is the owner of the originating IP?
**Answer:** `HostPapa`

![IPinfo lookup for 192.119.71.157 showing HostPapa ownership](/assets/img/posts/greenholt-phish/Screenshot_6.png)

The IP `192.119.71.157` is queried through [IPinfo.io](https://ipinfo.io), which returns the following:

| Field | Value |
|---|---|
| Location | Dallas, Texas, US |
| ASN | AS54290 — HostPapa |
| Hostname | `client-192-119-71-157.hostwindsdns.com` |
| AS Type | Hosting |

> **Red flag #2 — Shared hosting origin.** A marine company conducting international SWIFT transfers has no legitimate reason to send email from a shared hosting provider in Texas. Legitimate corporate mail originates from dedicated infrastructure — typically Microsoft 365, Google Workspace, or an on-premises mail server aligned with the domain's published SPF records.

---

## DNS authentication records

### Q7 — What is the full SPF record for the Return-Path domain?
**Answer:** `v=spf1 include:spf.protection.outlook.com -all`

The Return-Path domain — `mutawamarine.com` — is queried using [dmarcian's SPF Surveyor](https://dmarcian.com/spf-survey/).

> *Screenshots for Q7 (SPF Surveyor tool and result) to be added.*

The SPF record authorizes only Microsoft's mail infrastructure (`spf.protection.outlook.com`). The `-all` qualifier enforces a hard fail for any sender not on the list. Since this email originated from `192.119.71.157` (HostPapa), it should have been **rejected or flagged** by a correctly configured receiving server.

---

### Q8 — What is the complete DMARC record for the Return-Path domain?
**Answer:** `v=DMARC1; p=quarantine; fo=1`

The DMARC record is retrieved using [dmarcian's DMARC Inspector](https://dmarcian.com/dmarc-inspector/).

> *Screenshot for Q8 (DMARC result) to be added.*

The `p=quarantine` policy instructs receiving servers to quarantine — not deliver to the inbox — any message that fails DMARC alignment. Combined with the SPF failure observed in the message source, this email should have been quarantined automatically. The fact that it reached a recipient inbox suggests the receiving server was not enforcing DMARC policy.

---

## Attachment analysis

### Q9 — What is the file name of the attachment?
**Answer:** `SWT_#09674321____PDF__.CAB`

![Attachment visible at the bottom of the Thunderbird email view](/assets/img/posts/greenholt-phish/Screenshot_10.png)

> **Red flag #3 — Filename obfuscation.** The filename is engineered to suggest a PDF document while carrying a `.CAB` (Windows Cabinet Archive) extension. The excessive underscores pad the name to visually resemble a document reference code, making it appear routine to an unsuspecting recipient.

---

## File hashing and VirusTotal

### Q10 — What is the SHA256 hash of the attachment?
**Answer:** `2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f`

The attachment is saved to the TryHackMe virtual machine's Desktop directory and hashed using the terminal:

![Terminal showing sha256sum output for the attachment](/assets/img/posts/greenholt-phish/Screenshot_11.png)

```bash
cd Desktop
sha256sum SWT_#09674321____PDF__.CAB
```

```
2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f  SWT_#09674321____PDF__.CAB
```

---

### Q11 — What is the attachment's file size in KB?
**Answer:** `400.26 KB`

The SHA256 hash is submitted to [VirusTotal](https://www.virustotal.com) for analysis.

![VirusTotal Detection tab — 50/63 vendors flagged as malicious, file size highlighted](/assets/img/posts/greenholt-phish/Screenshot_12.png)

The result is immediate and unambiguous: **50 out of 63 security vendors flagged the file as malicious**. The popular threat label is `trojan.msil/loki`, with threat categories including `trojan`, `ransomware`, and `downloader`. Family labels include `msil`, `loki`, and `agensla`.

---

### Q12 — What is the actual file type of the attachment?
**Answer:** `RAR`

Switching to the **Details** tab in VirusTotal reveals the true nature of the file:

![VirusTotal Details tab — file type identified as RAR](/assets/img/posts/greenholt-phish/Screenshot_13.png)

| Property | Value |
|---|---|
| File type | RAR (compressed) |
| Magic | RAR archive data, v5 |
| TrID | RAR compressed archive (v5.0) — 61.5% |
| File size | 400.26 KB (409,868 bytes) |
| MD5 | `f4dd3456cdb1976a145c1179a4d461ec` |
| SHA-1 | `5a2bb8188377c15c036843b4a6ab9b0c0f2c1607` |

> **Red flag #4 — Triple-layer obfuscation.** The attachment uses three layers of deception simultaneously: (1) a filename containing `PDF` to suggest a harmless document, (2) a `.CAB` extension to bypass simple file-type filters, and (3) an actual RAR archive containing what VirusTotal classifies as a Loki infostealer/downloader payload. A naive user opening this file expecting a payment receipt would instead be executing malware.

---

## IOC summary

| IOC type | Value |
|---|---|
| Sender display name | Mr. James Jackson |
| Sender email | `info@mutawamarine.com` |
| Reply-To (attacker inbox) | `info.mutawamarine@mail.com` |
| Originating IP | `192.119.71.157` |
| IP owner / ASN | HostPapa — AS54290 |
| SPF result | Fail |
| DMARC policy | Quarantine (`p=quarantine`) |
| Attachment filename | `SWT_#09674321____PDF__.CAB` |
| True file type | RAR archive v5 |
| Threat label | `trojan.msil/loki` |
| SHA256 | `2e91c533615a9bb8929ac4bb76707b2444597ce063d84a4b33525e25074fff3f` |
| MD5 | `f4dd3456cdb1976a145c1179a4d461ec` |
| VT detection ratio | 50/63 |

---

## What I learned

This room demonstrates that a convincing phishing email does not require sophisticated infrastructure — only social engineering and a recipient who skips the verification steps.

The key takeaways:

- **Display names and From addresses prove nothing.** The only reliable sender signal is the SMTP routing chain and authentication results (SPF, DKIM, DMARC). Always read the raw message source.
- **SPF failure is a hard signal.** When `Received-SPF: fail` appears in the headers, the email did not originate from infrastructure the domain owner authorized. That alone should trigger escalation.
- **Reply-To mismatches are a BEC hallmark.** Separating the `From` domain from the `Reply-To` address is a deliberate tactic to redirect victim responses while maintaining a veneer of legitimacy in the visible header.
- **File extensions lie.** The `.CAB` extension and PDF-styled filename were both deliberate misdirection. True file type identification — via magic bytes and tools like VirusTotal — is always necessary before drawing conclusions from a filename.
- **VirusTotal is a force multiplier.** A single SHA256 hash lookup surfaced the threat family, detection ratio, historical submission data, and file properties in seconds. In a real SOC environment, these IOCs feed directly into SIEM rules, EDR blocks, and threat intelligence platforms.

The full investigation chain — headers → SPF/DMARC → IP intelligence → attachment hashing → VirusTotal — is a repeatable playbook applicable to any suspicious email, and this room is a clean, well-constructed example of it.
