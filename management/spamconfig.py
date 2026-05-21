import os
import re
import subprocess

import utils

# File paths for the various configuration files.
SPAMASSASSIN_LOCAL_CF = "/etc/spamassassin/local.cf"
SPAMASSASSIN_LOCAL_LISTS_CF = "/etc/spamassassin/local_lists.cf"
SPAMASSASSIN_MIAB_SPF_DMARC_CF = "/etc/spamassassin/miab_spf_dmarc.cf"
POSTGREY_DEFAULTS = "/etc/default/postgrey"
POSTGREY_WHITELIST_CLIENTS_LOCAL = "/etc/postgrey/whitelist_clients.local"
POSTFIX_MAIN_CF = "/etc/postfix/main.cf"
POSTFIX_SENDER_ACCESS = "/etc/postfix/sender_access"

# Default values.
DEFAULT_SPAM_THRESHOLD = 5.0
DEFAULT_GREYLISTING_DELAY = 180

# -----------------------------------------------------------------------
# Spam Settings (threshold, greylisting toggle, greylisting delay)
# -----------------------------------------------------------------------

def get_spam_config(env):
	"""Return the current spam configuration as a dict."""
	return {
		"spamassassin_threshold": _get_spamassassin_threshold(),
		"greylisting_enabled": _is_greylisting_enabled(),
		"greylisting_delay": _get_greylisting_delay(),
		"spamhaus_dqs_key": _get_spam_setting("spamhaus_dqs_key", ""),
		"spamhaus_zen_enabled": _get_spam_setting("spamhaus_zen_enabled", True),
		"spamhaus_dbl_enabled": _get_spam_setting("spamhaus_dbl_enabled", True),
		"spamhaus_zrd_enabled": _get_spam_setting("spamhaus_zrd_enabled", False),
	}

def set_spam_config(env, threshold=None, greylisting_enabled=None, greylisting_delay=None, spamhaus_dqs_key=None, spamhaus_zen=None, spamhaus_dbl=None, spamhaus_zrd=None):
	"""Apply spam configuration changes and restart affected services."""
	msgs = []

	if threshold is not None:
		threshold = float(threshold)
		if not (1.0 <= threshold <= 10.0):
			raise ValueError("Spam threshold must be between 1.0 and 10.0.")
		_set_spamassassin_threshold(threshold)
		msgs.append(f"SpamAssassin threshold set to {threshold}.")

	if greylisting_delay is not None:
		greylisting_delay = int(greylisting_delay)
		if not (60 <= greylisting_delay <= 600):
			raise ValueError("Greylisting delay must be between 60 and 600 seconds.")
		_set_greylisting_delay(greylisting_delay, env)
		msgs.append(f"Greylisting delay set to {greylisting_delay} seconds.")

	if greylisting_enabled is not None:
		enabled = greylisting_enabled if isinstance(greylisting_enabled, bool) else (greylisting_enabled.lower() == "true")
		_set_greylisting_enabled(enabled)
		msgs.append("Greylisting {}.".format("enabled" if enabled else "disabled"))

	postfix_needs_restart = False
	if spamhaus_dqs_key is not None or spamhaus_zen is not None or spamhaus_dbl is not None or spamhaus_zrd is not None:
		postfix_needs_restart = True
		if spamhaus_dqs_key is not None:
			key = spamhaus_dqs_key.strip()
			if key and not re.match(r"^[a-zA-Z0-9]+$", key):
				raise ValueError("Spamhaus DQS API key must be alphanumeric.")

	# Persist to settings.yaml so setup scripts can restore.
	_save_spam_settings_to_yaml(env, threshold, greylisting_enabled, greylisting_delay, spamhaus_dqs_key, spamhaus_zen, spamhaus_dbl, spamhaus_zrd)

	if postfix_needs_restart:
		_apply_postfix_spamhaus_rules(env)

	# Restart affected services.
	if threshold is not None:
		_restart_service("spampd")
	if greylisting_enabled is not None or greylisting_delay is not None:
		_restart_service("postgrey")
		_restart_service("postfix")
	elif postfix_needs_restart:
		_restart_service("postfix")

	return " ".join(msgs) if msgs else "OK"


def _get_spamassassin_threshold():
	"""Parse required_score from SpamAssassin local.cf."""
	try:
		with open(SPAMASSASSIN_LOCAL_CF, "r", encoding="utf-8") as f:
			for line in f:
				line = line.strip()
				if line.startswith("#"):
					continue
				m = re.match(r"required_score\s+([\d.]+)", line)
				if m:
					return float(m.group(1))
	except FileNotFoundError:
		pass
	return DEFAULT_SPAM_THRESHOLD


def _set_spamassassin_threshold(threshold):
	"""Set required_score in SpamAssassin local.cf using editconf."""
	utils.shell("check_call", [
		"python3", "/usr/local/lib/mailinabox/editconf.py",
		SPAMASSASSIN_LOCAL_CF, "-s",
		f"required_score={threshold}"
	])


def _is_greylisting_enabled():
	"""Check if postgrey is in Postfix's smtpd_recipient_restrictions."""
	try:
		restrictions = utils.shell("check_output", [
			"postconf", "-h", "smtpd_recipient_restrictions"
		]).strip()
		return "check_policy_service inet:127.0.0.1:10023" in restrictions
	except (subprocess.CalledProcessError, FileNotFoundError):
		return True  # default: assume enabled


def _set_greylisting_enabled(enabled):
	"""Toggle postgrey in Postfix's smtpd_recipient_restrictions."""
	try:
		restrictions = utils.shell("check_output", [
			"postconf", "-h", "smtpd_recipient_restrictions"
		]).strip()
	except (subprocess.CalledProcessError, FileNotFoundError):
		return

	postgrey_check = "check_policy_service inet:127.0.0.1:10023"
	parts = [p.strip() for p in restrictions.split(",") if p.strip()]

	if enabled:
		# Add postgrey if not present — insert before the last entry
		# (which is typically check_policy_service inet:127.0.0.1:12340 for rspamd/opendmarc).
		if postgrey_check not in parts:
			# Insert after reject_unlisted_recipient if present, otherwise append.
			try:
				idx = parts.index("reject_unlisted_recipient") + 1
			except ValueError:
				idx = len(parts)
			parts.insert(idx, postgrey_check)
	else:
		# Remove postgrey.
		parts = [p for p in parts if p != postgrey_check]

	new_restrictions = ", ".join(parts)
	utils.shell("check_call", [
		"postconf", f"smtpd_recipient_restrictions={new_restrictions}"
	])


def _get_greylisting_delay():
	"""Parse the --delay value from /etc/default/postgrey."""
	try:
		with open(POSTGREY_DEFAULTS, "r", encoding="utf-8") as f:
			for line in f:
				m = re.search(r"--delay=(\d+)", line)
				if m:
					return int(m.group(1))
	except FileNotFoundError:
		pass
	return DEFAULT_GREYLISTING_DELAY


def _set_greylisting_delay(delay, env):
	"""Update the --delay value in /etc/default/postgrey."""
	# Read the current POSTGREY_OPTS line, replace the --delay value.
	storage_root = env.get("STORAGE_ROOT", "/home/user-data")
	try:
		with open(POSTGREY_DEFAULTS, "r", encoding="utf-8") as f:
			content = f.read()
	except FileNotFoundError:
		return

	# Replace the --delay=NNN portion.
	new_content = re.sub(r"--delay=\d+", f"--delay={delay}", content)
	if new_content != content:
		with open(POSTGREY_DEFAULTS, "w", encoding="utf-8") as f:
			f.write(new_content)


def _get_spam_setting(key, default_val):
	"""Read a direct value from settings.yaml."""
	env = utils.load_environment()
	config = utils.load_settings(env)
	return config.get("spam", {}).get(key, default_val)


def _apply_postfix_spamhaus_rules(env):
	"""Apply or remove the Spamhaus rules in Postfix smtpd restrictions based on yaml settings."""
	try:
		recip = utils.shell("check_output", ["postconf", "-h", "smtpd_recipient_restrictions"]).strip()
		sender = utils.shell("check_output", ["postconf", "-h", "smtpd_sender_restrictions"]).strip()
	except (subprocess.CalledProcessError, FileNotFoundError):
		return
		
	config = utils.load_settings(env).get("spam", {})
	key = config.get("spamhaus_dqs_key", "").strip()
	zen_enabled = config.get("spamhaus_zen_enabled", True)
	dbl_enabled = config.get("spamhaus_dbl_enabled", True)
	zrd_enabled = config.get("spamhaus_zrd_enabled", False)
	
	# Strip existing Spamhaus RBL rules
	recip = re.sub(r',?\s*reject_rbl_client [a-zA-Z0-9\.]*zen\.(dq\.)?spamhaus\.(org|net)[^\,]*', '', recip)
	sender = re.sub(r',?\s*reject_rhsbl_sender [a-zA-Z0-9\.]*dbl\.(dq\.)?spamhaus\.(org|net)[^\,]*', '', sender)
	sender = re.sub(r',?\s*reject_rhsbl_sender [a-zA-Z0-9\.]*zrd\.(dq\.)?spamhaus\.(org|net)[^\,]*', '', sender)
	
	zen_target = f"{key}.zen.dq.spamhaus.net" if key else "zen.spamhaus.org"
	dbl_target = f"{key}.dbl.dq.spamhaus.net" if key else "dbl.spamhaus.org"
	zrd_target = f"{key}.zrd.dq.spamhaus.net" if key else "zrd.spamhaus.org"
	
	if zen_enabled:
		parts = [p.strip() for p in recip.split(',') if p.strip()]
		try:
			idx = parts.index("reject_unlisted_recipient")
		except ValueError:
			idx = len(parts)
		parts.insert(idx, f"reject_rbl_client {zen_target}=127.0.0.[2..11]")
		recip = ", ".join(parts)
	
	if dbl_enabled:
		sender += f", reject_rhsbl_sender {dbl_target}=127.0.1.[2..99]"
	if zrd_enabled:
		sender += f", reject_rhsbl_sender {zrd_target}=127.0.2.[2..24]"
	
	utils.shell("check_call", ["postconf", f"smtpd_recipient_restrictions={recip}"])
	utils.shell("check_call", ["postconf", f"smtpd_sender_restrictions={sender}"])


def _save_spam_settings_to_yaml(env, threshold, greylisting_enabled, greylisting_delay, spamhaus_dqs_key, spamhaus_zen, spamhaus_dbl, spamhaus_zrd):
	"""Persist spam settings to settings.yaml."""
	config = utils.load_settings(env)
	spam = config.get("spam", {})

	if threshold is not None:
		spam["spamassassin_threshold"] = float(threshold)
	if greylisting_enabled is not None:
		enabled = greylisting_enabled if isinstance(greylisting_enabled, bool) else (greylisting_enabled.lower() == "true")
		spam["greylisting_enabled"] = enabled
	if greylisting_delay is not None:
		spam["greylisting_delay"] = int(greylisting_delay)
	if spamhaus_dqs_key is not None:
		spam["spamhaus_dqs_key"] = spamhaus_dqs_key.strip()
	if spamhaus_zen is not None:
		spam["spamhaus_zen_enabled"] = (spamhaus_zen if isinstance(spamhaus_zen, bool) else (spamhaus_zen.lower() == "true"))
	if spamhaus_dbl is not None:
		spam["spamhaus_dbl_enabled"] = (spamhaus_dbl if isinstance(spamhaus_dbl, bool) else (spamhaus_dbl.lower() == "true"))
	if spamhaus_zrd is not None:
		spam["spamhaus_zrd_enabled"] = (spamhaus_zrd if isinstance(spamhaus_zrd, bool) else (spamhaus_zrd.lower() == "true"))

	config["spam"] = spam
	utils.write_settings(config, env)


# -----------------------------------------------------------------------
# Whitelist / Blacklist Management
# -----------------------------------------------------------------------

def get_spam_lists(env):
	"""Return all whitelist and blacklist entries."""
	return {
		"spamassassin_whitelist": _read_sa_list("whitelist_from"),
		"spamassassin_blacklist": _read_sa_list("blacklist_from"),
		"postgrey_whitelist": _read_postgrey_whitelist(),
		"postfix_blocked_senders": _read_postfix_blocked_senders(),
	}


# --- SpamAssassin whitelist_from / blacklist_from ---

def _read_sa_list(directive):
	"""Read entries for a given SA directive from local_lists.cf."""
	entries = []
	try:
		with open(SPAMASSASSIN_LOCAL_LISTS_CF, "r", encoding="utf-8") as f:
			for line in f:
				line = line.strip()
				if line.startswith("#") or not line:
					continue
				m = re.match(re.escape(directive) + r"\s+(.+)", line, re.IGNORECASE)
				if m:
					entries.append(m.group(1).strip())
	except FileNotFoundError:
		pass
	return entries


def _write_sa_list_file(whitelist_entries, blacklist_entries):
	"""Rewrite the entire local_lists.cf from the provided lists."""
	lines = [
		"# Mail-in-a-Box SpamAssassin Whitelist/Blacklist",
		"# Managed by the admin control panel. Do not edit manually.",
		""
	]
	for entry in whitelist_entries:
		lines.append(f"whitelist_from {entry}")
	if whitelist_entries and blacklist_entries:
		lines.append("")
	for entry in blacklist_entries:
		lines.append(f"blacklist_from {entry}")
	lines.append("")

	with open(SPAMASSASSIN_LOCAL_LISTS_CF, "w", encoding="utf-8") as f:
		f.write("\n".join(lines))


def add_spamassassin_whitelist(entry, env):
	"""Add a whitelist_from entry to SpamAssassin."""
	entry = entry.strip()
	validate_list_entry(entry, "spamassassin")

	current = _read_sa_list("whitelist_from")
	if entry.lower() in [e.lower() for e in current]:
		return "Entry already exists."

	current.append(entry)
	_write_sa_list_file(current, _read_sa_list("blacklist_from"))
	_restart_service("spampd")
	_save_lists_to_yaml(env)
	return "OK"


def remove_spamassassin_whitelist(entry, env):
	"""Remove a whitelist_from entry from SpamAssassin."""
	entry = entry.strip()
	current = _read_sa_list("whitelist_from")
	updated = [e for e in current if e.lower() != entry.lower()]
	if len(updated) == len(current):
		return "Entry not found."

	_write_sa_list_file(updated, _read_sa_list("blacklist_from"))
	_restart_service("spampd")
	_save_lists_to_yaml(env)
	return "OK"


def add_spamassassin_blacklist(entry, env):
	"""Add a blacklist_from entry to SpamAssassin."""
	entry = entry.strip()
	validate_list_entry(entry, "spamassassin")

	current = _read_sa_list("blacklist_from")
	if entry.lower() in [e.lower() for e in current]:
		return "Entry already exists."

	current.append(entry)
	_write_sa_list_file(_read_sa_list("whitelist_from"), current)
	_restart_service("spampd")
	_save_lists_to_yaml(env)
	return "OK"


def remove_spamassassin_blacklist(entry, env):
	"""Remove a blacklist_from entry from SpamAssassin."""
	entry = entry.strip()
	current = _read_sa_list("blacklist_from")
	updated = [e for e in current if e.lower() != entry.lower()]
	if len(updated) == len(current):
		return "Entry not found."

	_write_sa_list_file(_read_sa_list("whitelist_from"), updated)
	_restart_service("spampd")
	_save_lists_to_yaml(env)
	return "OK"


# --- Postgrey whitelist_clients.local ---

def _read_postgrey_whitelist():
	"""Read custom entries from postgrey whitelist_clients.local."""
	entries = []
	try:
		with open(POSTGREY_WHITELIST_CLIENTS_LOCAL, "r", encoding="utf-8") as f:
			for line in f:
				line = line.strip()
				if line.startswith("#") or not line:
					continue
				entries.append(line)
	except FileNotFoundError:
		pass
	return entries


def _write_postgrey_whitelist(entries):
	"""Rewrite the postgrey whitelist_clients.local file."""
	lines = [
		"# Mail-in-a-Box Postgrey Custom Whitelist",
		"# Managed by the admin control panel. Do not edit manually.",
		""
	]
	for entry in entries:
		lines.append(entry)
	lines.append("")

	with open(POSTGREY_WHITELIST_CLIENTS_LOCAL, "w", encoding="utf-8") as f:
		f.write("\n".join(lines))


def add_postgrey_whitelist(entry, env):
	"""Add a domain/IP to the postgrey custom whitelist."""
	entry = entry.strip()
	validate_list_entry(entry, "postgrey")

	current = _read_postgrey_whitelist()
	if entry.lower() in [e.lower() for e in current]:
		return "Entry already exists."

	current.append(entry)
	_write_postgrey_whitelist(current)
	_restart_service("postgrey")
	_save_lists_to_yaml(env)
	return "OK"


def remove_postgrey_whitelist(entry, env):
	"""Remove a domain/IP from the postgrey custom whitelist."""
	entry = entry.strip()
	current = _read_postgrey_whitelist()
	updated = [e for e in current if e.lower() != entry.lower()]
	if len(updated) == len(current):
		return "Entry not found."

	_write_postgrey_whitelist(updated)
	_restart_service("postgrey")
	_save_lists_to_yaml(env)
	return "OK"


# --- Postfix sender_access (hard-block) ---

def _read_postfix_blocked_senders():
	"""Read entries from /etc/postfix/sender_access."""
	entries = []
	try:
		with open(POSTFIX_SENDER_ACCESS, "r", encoding="utf-8") as f:
			for line in f:
				line = line.strip()
				if line.startswith("#") or not line:
					continue
				# Format: <sender> REJECT [optional reason]
				parts = line.split()
				if len(parts) >= 2 and parts[1].upper() == "REJECT":
					entries.append(parts[0])
	except FileNotFoundError:
		pass
	return entries


def _write_postfix_blocked_senders(entries):
	"""Rewrite /etc/postfix/sender_access and rebuild the hash."""
	lines = [
		"# Mail-in-a-Box Blocked Senders",
		"# Managed by the admin control panel. Do not edit manually.",
		""
	]
	for entry in entries:
		lines.append(f"{entry} REJECT")
	lines.append("")

	with open(POSTFIX_SENDER_ACCESS, "w", encoding="utf-8") as f:
		f.write("\n".join(lines))

	# Rebuild the hash db so Postfix can read it.
	utils.shell("check_call", ["postmap", POSTFIX_SENDER_ACCESS])


def _ensure_postfix_sender_access():
	"""Ensure check_sender_access is in smtpd_sender_restrictions if sender_access exists."""
	access_check = f"check_sender_access hash:{POSTFIX_SENDER_ACCESS}"
	try:
		restrictions = utils.shell("check_output", [
			"postconf", "-h", "smtpd_sender_restrictions"
		]).strip()
	except (subprocess.CalledProcessError, FileNotFoundError):
		return

	if access_check in restrictions:
		return  # already present

	parts = [p.strip() for p in restrictions.split(",") if p.strip()]
	# Insert at the beginning so blocked senders are checked first.
	parts.insert(0, access_check)
	new_restrictions = ",".join(parts)
	utils.shell("check_call", [
		"postconf", f"smtpd_sender_restrictions={new_restrictions}"
	])


def add_postfix_blocked_sender(entry, env):
	"""Add a sender to the Postfix hard-block list."""
	entry = entry.strip()
	validate_list_entry(entry, "postfix")

	current = _read_postfix_blocked_senders()
	if entry.lower() in [e.lower() for e in current]:
		return "Entry already exists."

	current.append(entry)
	_write_postfix_blocked_senders(current)
	_ensure_postfix_sender_access()
	_restart_service("postfix")
	_save_lists_to_yaml(env)
	return "OK"


def remove_postfix_blocked_sender(entry, env):
	"""Remove a sender from the Postfix hard-block list."""
	entry = entry.strip()
	current = _read_postfix_blocked_senders()
	updated = [e for e in current if e.lower() != entry.lower()]
	if len(updated) == len(current):
		return "Entry not found."

	_write_postfix_blocked_senders(updated)
	_restart_service("postfix")
	_save_lists_to_yaml(env)
	return "OK"


# -----------------------------------------------------------------------
# Validation
# -----------------------------------------------------------------------

def validate_list_entry(entry, list_type):
	"""Validate a whitelist/blacklist entry based on the list type."""
	if not entry:
		raise ValueError("Entry cannot be empty.")

	if list_type == "spamassassin":
		# SpamAssassin whitelist_from/blacklist_from supports:
		#   user@domain.com, *@domain.com, *@*.domain.com
		if not re.match(r"^[\w.*+\-]+@[\w.*\-]+\.\w+$", entry):
			raise ValueError(
				"Invalid SpamAssassin entry. Use an email address (user@example.com) "
				"or a wildcard pattern (*@example.com)."
			)

	elif list_type == "postgrey":
		# Postgrey whitelist_clients supports:
		#   domain.com, subdomain.example.com, IP addresses, CIDR ranges
		if not re.match(r"^[\w.\-]+\.\w+$", entry) and \
		   not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$", entry):
			raise ValueError(
				"Invalid postgrey entry. Use a domain name (example.com) "
				"or an IP address/CIDR (10.0.0.1 or 10.0.0.0/8)."
			)

	elif list_type == "postfix":
		# Postfix sender_access supports:
		#   user@domain.com or @domain.com (blocks entire domain)
		if not re.match(r"^[\w.+\-]+@[\w.\-]+\.\w+$", entry) and \
		   not re.match(r"^@[\w.\-]+\.\w+$", entry):
			raise ValueError(
				"Invalid Postfix entry. Use an email address (user@example.com) "
				"or a domain (@example.com)."
			)
	else:
		raise ValueError(f"Unknown list type: {list_type}")


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

def _restart_service(service_name):
	"""Restart a system service."""
	try:
		utils.shell("check_call", ["systemctl", "restart", service_name])
	except subprocess.CalledProcessError:
		# Service may not exist (e.g., on a dev machine).
		pass


def _save_lists_to_yaml(env):
	"""Persist the current list entries to settings.yaml for durability."""
	config = utils.load_settings(env)
	spam = config.get("spam", {})

	spam["spamassassin_whitelist"] = _read_sa_list("whitelist_from")
	spam["spamassassin_blacklist"] = _read_sa_list("blacklist_from")
	spam["postgrey_whitelist"] = _read_postgrey_whitelist()
	spam["postfix_blocked_senders"] = _read_postfix_blocked_senders()

	config["spam"] = spam
	utils.write_settings(config, env)
