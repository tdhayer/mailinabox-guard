# Contributing

Mail-in-a-Box Guard is an open-source project. Your contributions and pull requests are welcome.

## Development

To start developing Mail-in-a-Box Guard, [clone the repository](https://github.com/tdhayer/mailinabox-guard) and familiarize yourself with the code.

    $ git clone https://github.com/tdhayer/mailinabox-guard

### Vagrant and VirtualBox

We recommend you use [Vagrant](https://www.vagrantup.com/intro/getting-started/install.html) and [VirtualBox](https://www.virtualbox.org/wiki/Downloads) for local development. Please install them first.

With Vagrant set up, the following should boot up Mail-in-a-Box Guard inside a virtual machine:

    $ vagrant up --provision

_If you're seeing an error message about your *IP address being listed in the Spamhaus Block List*, simply uncomment the `export SKIP_NETWORK_CHECKS=1` line in the `Vagrantfile`. It's normal, as you're likely using a dynamic IP address assigned by your Internet provider._

### Modifying your `hosts` file

After a while, Mail-in-a-Box Guard will be available at `192.168.56.4` (unless you changed that in your `Vagrantfile`). To be able to use the web interface, we recommend adding a hostname to your `hosts` file:

    $ echo "192.168.56.4 mailinabox.lan" | sudo tee -a /etc/hosts

You should now be able to navigate to https://mailinabox.lan/admin using your browser. There should be an initial admin user with the name `me@mailinabox.lan` and the password `12345678`.

### Making changes

Your working copy of Mail-in-a-Box Guard will be mounted inside your VM at `/vagrant`. Any change you make locally will appear inside your VM automatically.

Running `vagrant up --provision` again will repeat the installation with your modifications.

Alternatively, you can also ssh into the VM using:

    $ vagrant ssh

Once inside the VM, you can re-run individual parts of the setup:

    vm$ cd /vagrant
    vm$ sudo setup/management.sh # replace with script you'd like to re-run

### Tests

The project includes a comprehensive unit test suite under the `tests/` directory. Tests are configured in `pyproject.toml` and run via pytest.

**Running tests locally:**

```bash
# Install test dependencies
pip install pytest rtyaml "email_validator>=1.0.0" flask dnspython python-dateutil \
    expiringdict "qrcode[pil]" pyotp "webauthn>=2.7.0" "cbor2<6.0.0" \
    "idna>=2.0.0" "cryptography>=44.0.2" psutil b2sdk boto3

# Run the full test suite
python -m pytest
```

**Current test files:**

| File | Coverage |
|---|---|
| `test_dashboard_apis.py` | API endpoints, spam settings, session idle status |
| `test_status_checks.py` | System status check logic |
| `test_mfa.py` | TOTP and WebAuthn multi-factor authentication |
| `test_dmarc_alerts.py` | DMARC alert processing |
| `test_password_policy.py` | Password complexity validation rules |
| `test_audit.py` | Audit log writes, reads, pagination, category filtering |
| `test_spam_config_path.py` | Dynamic editconf.py path resolution |

Writing and contributing tests is a great start if you are looking for a way to help improve codebase stability.

### CI/CD Pipeline

Every push and pull request to `main` triggers the following automated checks:

* **Ruff** — Python lint and format checks
* **ShellCheck** — Bash script analysis for `setup/` and `management/`
* **Python syntax matrix** — Compilation across Python 3.10, 3.11, 3.12, and 3.13
* **pytest** — Full unit test suite
* **Bandit** — Static security analysis for common vulnerabilities
* **pip-audit** — Dependency vulnerability scanning
* **CodeQL** — GitHub's advanced code analysis (also runs weekly)
* **Version sync** — Validates consistency across `VERSION`, `CHANGELOG.md`, and `bootstrap.sh`

All checks must pass before merging to `main`. Tagged releases (`v*`) trigger an additional release pipeline that re-runs the full quality gate and publishes a GitHub Release with auto-extracted changelog notes.

## Public Domain Waiver

This project is in the public domain. Copyright and related rights in the work worldwide are waived through the [CC0 1.0 Universal public domain dedication][CC0]. See the LICENSE file in this directory.

All contributions to this project must be released under the same CC0 waiver. By submitting a pull request or patch, you are agreeing to comply with this waiver of copyright interest.

[CC0]: http://creativecommons.org/publicdomain/zero/1.0/

## Code of Conduct

This project has a [Code of Conduct](CODE_OF_CONDUCT.md). Please review it when joining our community.
