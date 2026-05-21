# Mail-in-a-Box Guard

A security-focused, modernized fork of the open-source [Mail-in-a-Box](https://github.com/mail-in-a-box/mailinabox) project, designed for administrators who need advanced edge controls, unified logs, active firewall integration, and hardened hardware authentication.

Original project by [@JoshData](https://github.com/JoshData) and [contributors](https://github.com/mail-in-a-box/mailinabox/graphs/contributors). Fork maintained by [@tdhayer](https://github.com/tdhayer).

---

## Key Enhancements & Features

Mail-in-a-Box Guard expands on the original ease-of-use philosophy by providing enterprise-grade system visibility and defense-in-depth directly from the control panel:

### 1. Hardened Multi-Factor Authentication (MFA)
* **YubiKey & Passkey (WebAuthn) Support**: Go beyond standard passwords. Register hardware security keys or built-in biometric authenticators directly in the administration panel.
* **Fallback Options**: Configure standard TOTP (Time-based One-Time Passwords) as a backup method.

### 2. Live Admin Dashboard & System Telemetry
* **Realtime Metrics**: Instant overview of CPU, memory, and disk usage.
* **Mail Queue Monitor**: Track pending outbound deliveries with queue counter gauges.
* **Interactive Traffic Flow Charts**: Visual charts mapping out received, sent, and blocked mail counts over time, built with Chart.js.

### 3. Integrated Firewall & Intrusion Prevention
* **Fail2ban GUI**: View active jails, jail health status, and real-time ban counters.
* **Active Blocking Controls**: Directly inspect lists of banned IP addresses, and manually ban or unban addresses with a single click in the UI.

### 4. Unified System Log Viewer
* **Secure Console Interface**: Read system logs (syslog, mail logs, nginx logs, and fail2ban logs) directly from the control panel.
* **Interactive Search**: Search, filter, and paginate through log entries in reverse chronological order for swift debugging.

### 5. Outbound Delivery Preference (IPv4/IPv6 Toggles)
* **Network Bindings**: Toggle Postfix preference to prefer or force IPv4/IPv6 for outgoing mail.
* **Delivery Routing**: Easily route outbound mail to bypass aggressive IPv6 spam blacklists on cloud VPS networks.

### 6. Edge Spam Controls
* **Granular Spam tuning**: Manage greylisting settings, modify greylisting delays, and customize SpamAssassin score thresholds to dynamically tune spam rejection rates.

---

## In The Box

Mail-in-a-Box Guard configures a fresh Ubuntu 22.04 LTS 64-bit machine into a hardened mail appliance:

* **SMTP** ([Postfix](http://www.postfix.org/)), **IMAP** ([Dovecot](http://dovecot.org/)), **CardDAV/CalDAV** ([Nextcloud](https://nextcloud.com/)), and **Exchange ActiveSync** ([z-push](http://z-push.org/))
* **Webmail** ([Roundcube](http://roundcube.net/)) with mail filtering rules and autoconfiguration profiles served by [Nginx](http://nginx.org/)
* **Spam Protection**: [SpamAssassin](https://spamassassin.apache.org/) and greylisting via [Postgrey](http://postgrey.schweikert.ch/)
* **DNS Server** ([nsd4](https://www.nlnetlabs.nl/projects/nsd/)) with automatic SPF, DKIM ([OpenDKIM](http://www.opendkim.org/)), DMARC, DNSSEC, DANE TLSA, MTA-STS, and SSHFP policy records
* **TLS Certificates**: Automatically generated and renewed via [Let's Encrypt](https://letsencrypt.org/)
* **Backups** ([Duplicity](http://duplicity.nongnu.org/)), firewall ([ufw](https://launchpad.net/ufw)), intrusion prevention ([fail2ban](http://www.fail2ban.org/)), and system status reporting

---

## Installation

See the setup guide on the original [Mail-in-a-Box website](https://mailinabox.email/guide.html) for general prerequisites.

Start with a completely fresh, vanilla **Ubuntu 22.04 LTS 64-bit** server. On the server:

1. Clone this fork repository:
   ```bash
   git clone https://github.com/tdhayer/mailinabox-guard.git
   cd mailinabox-guard
   ```

2. Run the interactive setup:
   ```bash
   sudo setup/start.sh
   ```

The script will automatically install necessary packages, configure services, and establish the administration daemon.

---

## Support & Contributing

* **Bugs & Issues**: Please report issues specific to the Guard edition on the [GitHub Issues](https://github.com/tdhayer/mailinabox-guard/issues) page.
* **Contributing**: Development takes place on GitHub. Check out the [Contributing Guidelines](CONTRIBUTING.md) to get started.

---

## License & History

This project is in the public domain and is dedicated to the public domain through the [CC0 1.0 Universal Waiver](LICENSE). 

### Acknowledgements
This project is built upon the wonderful foundation of [Mail-in-a-Box](https://github.com/mail-in-a-box/mailinabox) by Josh Tauberer, inspired by Alex Payne's Sovereign and Drew Crawford's "NSA-proof your email in 2 hours" guide.
