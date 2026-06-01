# Mail-in-a-Box Guard Security Guide

Mail-in-a-Box Guard turns a fresh Ubuntu 22.04 LTS 64-bit machine into a secure mail server appliance by installing and configuring various components.

This page documents the security posture of Mail-in-a-Box Guard. The term "box" is used below to mean a configured Mail-in-a-Box Guard server.

---

## Supported Versions

Security fixes are applied to the active Guard release line for Ubuntu 22.04.

Older tags may remain available for compatibility, but they may not receive the same security update cadence.

For the best security posture, run the latest tagged Guard release and keep setup reruns current.

---

## Reporting Security Vulnerabilities

Security vulnerabilities should be reported directly to the project maintainer [@tdhayer](https://github.com/tdhayer) or by opening a GitHub Security Advisory on the [repository security tab](https://github.com/tdhayer/mailinabox-guard/security).

When reporting, include:

* Affected version/tag
* Reproduction steps or proof-of-concept
* Potential impact and scope
* Any suggested mitigation if known

Public disclosure should wait until a fix or mitigation is available.

## Vulnerability Handling Process

The project aims to:

* Acknowledge new reports promptly
* Validate and triage severity
* Prepare and test a fix
* Publish release notes with remediation details

Time-to-fix depends on severity, exploitability, and upstream dependency constraints.

---

## Threat Model

Nothing is perfectly secure, and an adversary with sufficient resources can always penetrate a system.

The primary goal of Mail-in-a-Box Guard is to make deploying a secure mail server easy. We balance privacy and security concerns with the practicality of actually deploying the system. That means we make certain assumptions about adversaries. We assume that adversaries:

* Do not have physical access to the box.
* Have not been given Unix accounts on the box (all users with shell access are assumed trusted).

On the other hand, we do assume that adversaries are performing passive surveillance and, possibly, active man-in-the-middle attacks. And so:

* User credentials are always sent through SSH/TLS, never in the clear, with modern TLS settings.
* Outbound mail is sent with the highest level of TLS possible.
* The box advertises its support for [DANE TLSA](https://en.wikipedia.org/wiki/DNS-based_Authentication_of_Named_Entities), when DNSSEC is enabled at the domain name registrar, so that inbound mail is more likely to be transmitted securely.

---

## User Credentials & Access Hardening

### Services behind TLS

These services are protected by [TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security):

* **SMTP Submission (ports 465/587)**: Mail users submit outbound mail through SMTP with TLS (port 465) or STARTTLS (port 587).
* **IMAP/POP (ports 993/995)**: Mail users check for incoming mail through IMAP or POP over TLS.
* **HTTPS (port 443)**: Webmail, the Exchange/ActiveSync protocol, the administrative control panel, and static hosted websites are accessed over HTTPS.

The services all follow these rules:

* TLS certificates are generated with 2048-bit RSA keys and SHA-256 fingerprints. The box automatically provisions and renews TLS certificates using Let's Encrypt.
* Only TLSv1.2+ are offered (older SSL/TLS protocols are disabled).
* We track the [Mozilla Intermediate Ciphers Recommendation](https://wiki.mozilla.org/Security/Server_Side_TLS), balancing security with supporting a wide range of mail clients. Diffie-Hellman ciphers use a 2048-bit key for forward secrecy.
* HTTPS (port 443): The HTTPS Strict Transport Security header is set. A redirect from HTTP to HTTPS is offered. The [Qualys SSL Labs test](https://www.ssllabs.com/ssltest) reports an A+ grade.

### Multi-Factor Authentication (MFA) & Hardware Protection

Mail-in-a-Box Guard includes built-in MFA controls to protect the administration control panel:

* **Hardware Security (WebAuthn)**: Support for YubiKeys and modern biometric Passkeys (WebAuthn). This offers state-of-the-art protection against phishing and credential stuffing.
* **Standard TOTP**: Support for standard time-based one-time passcodes (like Google Authenticator or Authy) as a secondary fallback.
* **Login Security**: Password changes or modifications to MFA configurations immediately expire all other active admin login sessions.

### Password Policy

Mail-in-a-Box Guard enforces a modern password complexity policy for all user accounts:

* Minimum **10 characters** in length.
* At least **one uppercase** letter, **one lowercase** letter, **one digit**, and **one special character**.
* Passwords are validated server-side at creation and change time. Existing user passwords are not retroactively affected.
* The control panel provides a real-time floating checklist popover showing each requirement as the user types.
* A cryptographically secure password generator (using `crypto.getRandomValues()`) is available inline with one-click apply functionality.

### Password Storage

The passwords for mail users are stored on disk using the [SHA512-CRYPT](http://man7.org/linux/man-pages/man3/crypt.3.html) hashing scheme.

### Session Management

Admin control panel sessions include idle timeout protection:

* Sessions expire after **30 minutes** of inactivity. Each authenticated API request resets the idle timer.
* A visual countdown toast warns users **5 minutes** before session expiry, with a "Stay logged in" option that extends the session.
* On expiry, sessions are cleanly terminated and stored credentials are cleared.
* The absolute session lifetime (2 days via `ExpiringDict`) remains as the maximum session duration regardless of activity.

### Admin Action Audit Trail

All state-mutating administrative operations are logged to a SQLite database (`STORAGE_ROOT/admin/audit.sqlite`):

* **Tracked actions**: User management (add/remove/password change/privilege change/quota change), alias management, DNS updates, SSL operations, spam configuration changes, system operations (reboot, backup config, privacy settings, postfix config, mail queue), and security actions (fail2ban ban/unban, MFA enable/disable).
* **Logged data**: Timestamp (UTC ISO 8601), administrator email, action type, target entity, and optional details.
* **Access**: Viewable via a paginated, filterable panel in the Logs section of the control panel. Filterable by category (Users, Aliases, Spam, DNS, SSL, System, Security).

### Console Access

Console access (via SSH) is configured by the system image used to create the box. Mail-in-a-Box Guard does not set any console access settings, although it will audit SSH configuration and warn the administrator in the System Status Checks if insecure settings (like password-based login or root login) are active.

### Brute-force Attack Mitigation

`fail2ban` protects the box from brute-force login attacks by blocking offending IP addresses at the network level using the local firewall.

The following services are protected: SSH, IMAP (Dovecot), SMTP submission (Postfix), webmail (Roundcube), Nextcloud/CalDAV/CardDAV, and the Mail-in-a-Box Guard control panel.

Administrators can view Fail2ban statistics, inspect active jail lists, and manually ban/unban IP addresses directly within the control panel.

---

## Web Application Security

### Cross-Site Scripting (XSS) Protection

All user-controlled data (email addresses, quota values, connection metadata) is sanitized before injection into HTML using a global `escapeHtml()` helper function. This applies to:

* Modal confirmation dialogs in user management
* Active connections table in the dashboard
* Audit trail display in the logs panel

### Content Security Policy (CSP)

The box sets a hardened Content-Security-Policy header on admin panel responses, and also emits a stricter report-only policy during migration away from inline script allowances.

```text
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none';
Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none';
```

This constrains resource loading to approved sources, blocks framing, and provides visibility into inline-script dependencies before stricter enforcement is enabled.

---

## Outbound Mail Security

Email delivery protocols were not originally designed for secure networks. Mail-in-a-Box Guard uses modern extensions to secure outbound deliveries:

### DNSSEC

The first step in resolving the destination server for an email address is performing a DNS look-up for the MX record of the domain name. The box uses a locally-running DNSSEC-aware nameserver to perform the lookup. If the domain name has DNSSEC enabled, DNSSEC guards against DNS records being tampered with.

### Encryption

The box uses opportunistic encryption, meaning mail is encrypted in transit and protected from passive eavesdropping. Modern encryption settings (TLSv1.2 and later) are used to the extent the recipient server supports them.

### DANE

If the recipient's domain name supports DNSSEC and has published a [DANE TLSA](https://en.wikipedia.org/wiki/DNS-based_Authentication_of_Named_Entities) record, then on-the-wire encryption is forced between the box and the recipient MTA. The TLSA record contains a certificate fingerprint which the receiving MTA (server) must present to the box.

### Domain Policy Records

Domain policy records allow recipient MTAs to detect when the sender address domain is spoofed. All outbound mail is signed with [DKIM](https://en.wikipedia.org/wiki/DomainKeys_Identified_Mail) and "quarantine" [DMARC](https://en.wikipedia.org/wiki/DMARC) records are automatically set in DNS, along with strong [SPF](https://en.wikipedia.org/wiki/Sender_Policy_Framework) records.

### User Policy

The box restricts the envelope sender address (MAIL FROM address) that users may put into outbound mail. The envelope sender address must be either their own email address or an alias that they are listed as a permitted sender of.

---

## Incoming Mail Filtering

### Encryption Settings

As with outbound email, there is no way to require on-the-wire encryption of incoming mail from all senders. The box offers encryption (STARTTLS) but cannot require it. To give senders the best chance at making use of encryption, the box offers protocols back to TLSv1 and ciphers with key lengths as low as 112 bits. Modern clients will make use of the 256-bit ciphers and Diffie-Hellman ciphers with a 2048-bit key for perfect forward secrecy.

### MTA-STS

The box publishes a SMTP MTA Strict Transport Security ([SMTP MTA-STS](https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol#SMTP_MTA_Strict_Transport_Security)) policy (via DNS and HTTPS) in "enforce" mode. Senders that support MTA-STS will use a secure SMTP connection.

### DANE For Inbound Delivery

When DNSSEC is enabled at the box's domain name's registrar, DANE TLSA records are automatically published in DNS. Senders supporting DANE will enforce encryption on-the-wire between them and the box.

### Filters & Spam Control

Incoming mail is filtered to reject spam and malicious content:

* Senders are blocked if listed in the Spamhaus Zen blacklist or the Spamhaus Domain Block List (DBL). Optional Zero Reputation Domain (ZRD) blocking is available for newly registered domains.
* Administrators can configure a [Spamhaus DQS](https://www.spamhaus.com/product/data-query-service/) API key for enhanced blocklist queries that bypass public DNS resolver limitations.
* Greylisting (with [postgrey](http://postgrey.schweikert.ch/)) is used to delay and reduce automated spam. Delay duration is configurable.
* SpamAssassin scoring thresholds are tunable from the admin panel (range 1.0–10.0).
* Administrators can manage SpamAssassin whitelists and blacklists, Postgrey bypass lists, and Postfix blocked sender lists directly from the control panel.
