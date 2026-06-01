# Contributing

Thanks for helping improve Mail-in-a-Box Guard.

This document covers the expected workflow for development, testing, and release updates.

## Development Environment

Clone the repository:

```bash
git clone https://github.com/tdhayer/mailinabox-guard
cd mailinabox-guard
```

### Recommended local workflow (Vagrant)

Install [Vagrant](https://www.vagrantup.com/intro/getting-started/install.html) and [VirtualBox](https://www.virtualbox.org/wiki/Downloads), then provision:

```bash
vagrant up --provision
```

If your network causes Spamhaus preflight failures in development, uncomment `export SKIP_NETWORK_CHECKS=1` in `Vagrantfile`.

Optional hosts entry for browser access:

```bash
echo "192.168.56.4 mailinabox.lan" | sudo tee -a /etc/hosts
```

Admin URL:

```text
https://mailinabox.lan/admin
```

The default Vagrant test account is `me@mailinabox.lan` with password `12345678`.

## Re-running setup components

Inside the VM:

```bash
vagrant ssh
cd /vagrant
sudo setup/management.sh
```

Replace `setup/management.sh` with any setup script you are iterating on.

## Local Quality Checks

Install Python dependencies used by the management daemon and tests:

```bash
python -m pip install --upgrade \
  pytest rtyaml "email_validator>=1.0.0" exclusiveprocess \
  flask dnspython python-dateutil expiringdict gunicorn defusedxml \
  "qrcode[pil]" pyotp "webauthn>=2.7.0" "cbor2<6.0.0" \
  "idna>=2.0.0" "cryptography>=44.0.2" psutil postfix-mta-sts-resolver \
  b2sdk boto3
```

Run tests:

```bash
python -m pytest
```

Run lint gates used in CI:

```bash
python -m ruff check .
python -m ruff check management tests --select F,E9
python -m ruff format --check .
```

Run security scan used in CI:

```bash
python -m bandit -r management/ setup/ tools/ -ll -s B108,B310,B324
```

## CI Expectations

Every push and pull request to `main` is validated by:

* Ruff lint and format checks
* ShellCheck for setup and management scripts
* Python syntax matrix (3.10 through 3.13)
* pytest suite
* Bandit static analysis
* pip-audit dependency checks
* CodeQL analysis
* Version synchronization checks

Keep changes scoped and make sure all checks pass before requesting review.

## Documentation and Release Version Sync

When preparing a release, keep these files aligned:

* `VERSION`
* Top entry in `CHANGELOG.md`
* Default Ubuntu 22.04 `TAG=` in `setup/bootstrap.sh`

Validate locally:

```bash
python tools/version_sync_check.py
python tools/version_sync_check.py --tag v<version>
```

## Pull Request Guidance

Please include:

* Problem statement and rationale
* Scope of change
* Test and validation evidence
* Any migration or operator impact

For security-sensitive fixes, coordinate via the process in `security.md`.

## Public Domain Waiver

This project is in the public domain. Copyright and related rights are waived through the [CC0 1.0 Universal public domain dedication][CC0].

All contributions must be provided under the same CC0 waiver.

[CC0]: http://creativecommons.org/publicdomain/zero/1.0/

## Code of Conduct

All participation is subject to [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
