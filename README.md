# Mail-in-a-Box Guard

Mail-in-a-Box Guard is a security-focused fork of [Mail-in-a-Box](https://github.com/mail-in-a-box/mailinabox), maintained for operators who want stronger admin hardening, richer operational telemetry, and safer default workflows while retaining the original all-in-one mail server model.

Original project by [@JoshData](https://github.com/JoshData) and [contributors](https://github.com/mail-in-a-box/mailinabox/graphs/contributors). Guard fork maintained by [@tdhayer](https://github.com/tdhayer).

## Project Scope

Mail-in-a-Box Guard is optimized for single-node deployments and straightforward operations.

It is not positioned as a high-availability or horizontally scaled mail platform.

## What Guard Adds

Guard builds on upstream Mail-in-a-Box with additional controls and visibility, including:

* Hardened MFA with TOTP and WebAuthn (passkeys/security keys)
* Admin dashboard telemetry for queue, traffic, and system health
* Integrated fail2ban controls and security-focused status checks
* Unified logs view plus administrative audit trail
* Password policy enforcement and secure password generation
* Session idle timeout with warning flow and cleanup behavior
* Expanded spam controls (Spamhaus DQS, list management, tuning)
* DMARC and spam dashboard analytics for operational review

## Platform Support

### Active support

* Ubuntu 22.04 LTS (64-bit)

### Legacy compatibility tags

* Ubuntu 18.04 LTS remains tag-compatible with older branches only
* Ubuntu 14.04 LTS is no longer supported

## Installation

Review baseline prerequisites in the original [Mail-in-a-Box guide](https://mailinabox.email/guide.html), then use one of the methods below.

### Quick install (recommended)

```bash
curl -s https://raw.githubusercontent.com/tdhayer/mailinabox-guard/main/setup/bootstrap.sh | sudo bash
```

### Manual install

```bash
git clone https://github.com/tdhayer/mailinabox-guard.git
cd mailinabox-guard
sudo setup/start.sh
```

## Upgrade Paths

### Existing Guard installation

Run the same bootstrap command. The script fetches the latest supported tag and re-runs setup safely for in-place upgrades.

### Existing upstream Mail-in-a-Box installation

Bootstrap now includes migration preflight logic:

* If the current repository origin does not contain the target Guard tag, bootstrap switches origin to the Guard repository
* The previous origin is preserved as `upstream`
* Setup then continues with the requested Guard release tag

For safety, take a snapshot/backup before any in-place upgrade.

## Components In The Box

A fresh Ubuntu 22.04 host is configured as a full mail appliance, including:

* Postfix (SMTP), Dovecot (IMAP/POP), Roundcube (webmail)
* Nextcloud (CardDAV/CalDAV) and Z-Push (ActiveSync)
* NSD with SPF, DKIM, DMARC, DNSSEC, DANE TLSA, MTA-STS, and SSHFP support
* Automated TLS with Let's Encrypt
* SpamAssassin, Postgrey, fail2ban, UFW, and backup services

## Operations And Validation

After install or upgrade:

1. Sign in to the admin UI at `https://<your-hostname>/admin`
2. Review system checks and resolve warnings
3. Confirm mail flow and queue behavior
4. Confirm backup status and restore readiness

## Quality Gates

Pushes and pull requests to `main` run through automated quality controls:

* Ruff lint and format checks
* ShellCheck for setup/management scripts
* Python syntax matrix (3.10 through 3.13)
* pytest suite
* Bandit static analysis
* pip-audit dependency scanning
* CodeQL analysis (push and scheduled)
* Version synchronization checks across `VERSION`, `CHANGELOG.md`, and `setup/bootstrap.sh`

Tagged releases (`v*`) re-run validation and publish GitHub release notes extracted from the top changelog section.

## Documentation Index

* Contribution guide: [CONTRIBUTING.md](CONTRIBUTING.md)
* Security posture and disclosure policy: [security.md](security.md)
* Code of conduct: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
* Release history: [CHANGELOG.md](CHANGELOG.md)

## Support And Contributions

* Report issues: [GitHub Issues](https://github.com/tdhayer/mailinabox-guard/issues)
* Security reporting process: [security.md](security.md)
* Contribution workflow: [CONTRIBUTING.md](CONTRIBUTING.md)

## License

This project is dedicated to the public domain through [CC0 1.0](LICENSE).

## Acknowledgements

Mail-in-a-Box Guard is built on the foundation of [Mail-in-a-Box](https://github.com/mail-in-a-box/mailinabox).
