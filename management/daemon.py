#!/usr/local/lib/mailinabox/env/bin/python3
#
# The API can be accessed on the command line, e.g. use `curl` like so:
#    curl --user $(</var/lib/mailinabox/api.key): http://localhost:10222/mail/users
#
# During development, you can start the Mail-in-a-Box control panel
# by running this script, e.g.:
#
# service mailinabox stop # stop the system process
# DEBUG=1 management/daemon.py
# service mailinabox start # when done debugging, start it up again

import os, os.path, re, json, time, datetime, sys
import multiprocessing.pool

from functools import wraps

from flask import Flask, request, render_template, Response, send_from_directory, make_response

import auth, utils, audit
from mailconfig import get_mail_users, get_mail_users_ex, get_admins, add_mail_user, set_mail_password, remove_mail_user
from mailconfig import get_mail_user_privileges, add_remove_mail_user_privilege
from mailconfig import get_mail_aliases, get_mail_aliases_ex, get_mail_domains, add_mail_alias, remove_mail_alias
from mailconfig import get_mail_quota, set_mail_quota
from mfa import get_public_mfa_state, provision_totp, validate_totp_secret, enable_mfa, disable_mfa, provision_webauthn, register_webauthn
from spamconfig import get_spam_config, set_spam_config, get_spam_lists, \
	add_spamassassin_whitelist, remove_spamassassin_whitelist, \
	add_spamassassin_blacklist, remove_spamassassin_blacklist, \
	add_postgrey_whitelist, remove_postgrey_whitelist, \
	add_postfix_blocked_sender, remove_postfix_blocked_sender
import contextlib

env = utils.load_environment()

auth_service = auth.AuthService()

# We may deploy via a symbolic link, which confuses flask's template finding.
me = __file__
with contextlib.suppress(OSError):
	me = os.readlink(__file__)

# for generating CSRs we need a list of country codes
csr_country_codes = []
with open(os.path.join(os.path.dirname(me), "csr_country_codes.tsv"), encoding="utf-8") as f:
	for line in f:
		if line.strip() == "" or line.startswith("#"): continue
		code, name = line.strip().split("\t")[0:2]
		csr_country_codes.append((code, name))

app = Flask(__name__, template_folder=os.path.abspath(os.path.join(os.path.dirname(me), "templates")))

# Decorator to protect views that require a user with 'admin' privileges.
def authorized_personnel_only(viewfunc):
	@wraps(viewfunc)
	def newview(*args, **kwargs):
		# Authenticate the passed credentials, which is either the API key or a username:password pair
		# and an optional X-Auth-Token token.
		error = None
		privs = []

		try:
			email, privs = auth_service.authenticate(request, env)
		except ValueError as e:
			if "Rate limit exceeded" in str(e):
				return Response(json.dumps({
					"status": "rate-limited",
					"reason": str(e),
				})+"\n", status=429, mimetype='application/json')

			# Write a line in the log recording the failed login, unless no authorization header
			# was given which can happen on an initial request before a 403 response.
			if "Authorization" in request.headers:
				log_failed_login(request)

			# Authentication failed.
			error = str(e)

		# Authorized to access an API view?
		if "admin" in privs:
			# Store the email address of the logged in user so it can be accessed
			# from the API methods that affect the calling user.
			request.user_email = email
			request.user_privs = privs

			# Call view func.
			return viewfunc(*args, **kwargs)

		if not error:
			error = "You are not an administrator."

		# Not authorized. Return a 401 (send auth) and a prompt to authorize by default.
		status = 401
		headers = {
			'WWW-Authenticate': f'Basic realm="{auth_service.auth_realm}"',
			'X-Reason': error,
		}

		if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
			# Don't issue a 401 to an AJAX request because the user will
			# be prompted for credentials, which is not helpful.
			status = 403
			headers = None

		if request.headers.get('Accept') in {None, "", "*/*"}:
			# Return plain text output.
			return Response(error+"\n", status=status, mimetype='text/plain', headers=headers)
		# Return JSON output.
		return Response(json.dumps({
			"status": "error",
			"reason": error,
			})+"\n", status=status, mimetype='application/json', headers=headers)

	return newview

@app.errorhandler(401)
def unauthorized(error):
	return auth_service.make_unauthorized_response()

def json_response(data, status=200):
	return Response(json.dumps(data, indent=2, sort_keys=True)+'\n', status=status, mimetype='application/json')

###################################

# Control Panel (unauthenticated views)

@app.route('/')
def index():
	# Render the control panel. This route does not require user authentication
	# so it must be safe!

	no_users_exist = (len(get_mail_users(env)) == 0)
	no_admins_exist = (len(get_admins(env)) == 0)

	import boto3.s3
	backup_s3_hosts = [(r, f"s3.{r}.amazonaws.com") for r in boto3.session.Session().get_available_regions('s3')]


	return render_template('index.html',
		hostname=env['PRIMARY_HOSTNAME'],
		storage_root=env['STORAGE_ROOT'],

		no_users_exist=no_users_exist,
		no_admins_exist=no_admins_exist,

		backup_s3_hosts=backup_s3_hosts,
		csr_country_codes=csr_country_codes,
	)

# Create a session key by checking the username/password in the Authorization header.
@app.route('/login', methods=["POST"])
def login():
	# Is the caller authorized?
	try:
		email, privs = auth_service.authenticate(request, env, login_only=True)
	except ValueError as e:
		if "missing-totp-token" in str(e):
			return json_response({
				"status": "missing-totp-token",
				"reason": str(e),
			})
		if "missing-webauthn-token" in str(e):
			challenge_json = str(e).split("missing-webauthn-token:")[1]
			return json_response({
				"status": "missing-webauthn-token",
				"options": json.loads(challenge_json),
			})
		if "webauthn-library-unavailable" in str(e):
			return json_response({
				"status": "invalid",
				"reason": "Security key (WebAuthn) support is not available on the server. Please run the Mail-in-a-Box setup script to reinstall dependencies, then restart the service.",
			})
		if "Rate limit exceeded" in str(e):
			return json_response({
				"status": "rate-limited",
				"reason": str(e),
			}, status=429)
		# Log the failed login
		log_failed_login(request)
		return json_response({
			"status": "invalid",
			"reason": str(e),
		})

	# Return a new session for the user.
	resp = {
		"status": "ok",
		"email": email,
		"privileges": privs,
		"api_key": auth_service.create_session_key(email, env, type='login'),
	}

	app.logger.info("New login session created for %s", email)

	# Return.
	return json_response(resp)

@app.route('/logout', methods=["POST"])
def logout():
	try:
		email, _ = auth_service.authenticate(request, env, logout=True)
		app.logger.info("%s logged out", email)
	except ValueError:
		pass
	finally:
		return json_response({ "status": "ok" })

@app.route('/session/idle-status')
@authorized_personnel_only
def session_idle_status():
	import time
	session_key = None
	username = None
	if request.authorization:
		username = request.authorization.username
		session_key = request.authorization.password
	else:
		auth_header = request.headers.get('Authorization', '')
		if " " in auth_header:
			scheme, credentials = auth_header.split(maxsplit=1)
			if scheme == 'Basic':
				try:
					import base64
					credentials = base64.b64decode(credentials.encode('ascii')).decode('ascii')
					if ":" in credentials:
						username, session_key = credentials.split(':', maxsplit=1)
				except Exception:
					pass

	if username == auth_service.key:
		return json_response({
			"status": "ok",
			"remaining": 999999
		})

	if session_key and session_key in auth_service.sessions:
		session = auth_service.sessions[session_key]
		elapsed = time.time() - session.get("last_activity", 0)
		remaining = max(0, 1800 - int(elapsed))
		return json_response({
			"status": "ok",
			"remaining": remaining
		})

	return json_response({
		"status": "error",
		"reason": "No active session found."
	}, status=400)

# MAIL

@app.route('/mail/users')
@authorized_personnel_only
def mail_users():
	if request.args.get("format", "") == "json":
		return json_response(get_mail_users_ex(env, with_archived=True))
	return "".join(x+"\n" for x in get_mail_users(env))

@app.route('/mail/users/add', methods=['POST'])
@authorized_personnel_only
def mail_users_add():
	quota = request.form.get('quota', '0')
	try:
		res = add_mail_user(request.form.get('email', ''), request.form.get('password', ''), request.form.get('privileges', ''), quota, env)
		if not isinstance(res, tuple):
			audit.log_admin_action(request.user_email, "user_add", request.form.get('email', ''), f"privileges: {request.form.get('privileges', '')}, quota: {quota}", env)
		return res
	except ValueError as e:
		return (str(e), 400)

@app.route('/mail/users/quota', methods=['GET'])
@authorized_personnel_only
def get_mail_users_quota():
	email = request.values.get('email', '')
	quota = get_mail_quota(email, env)

	if request.values.get('text'):
		return quota

	return json_response({
		"email": email,
		"quota": quota
	})

@app.route('/mail/users/quota', methods=['POST'])
@authorized_personnel_only
def mail_users_quota():
	try:
		res = set_mail_quota(request.form.get('email', ''), request.form.get('quota'), env)
		audit.log_admin_action(request.user_email, "user_quota_change", request.form.get('email', ''), f"quota: {request.form.get('quota')}", env)
		return res
	except ValueError as e:
		return (str(e), 400)

@app.route('/mail/users/password', methods=['POST'])
@authorized_personnel_only
def mail_users_password():
	try:
		res = set_mail_password(request.form.get('email', ''), request.form.get('password', ''), env)
		audit.log_admin_action(request.user_email, "user_password_change", request.form.get('email', ''), None, env)
		return res
	except ValueError as e:
		return (str(e), 400)

@app.route('/mail/users/remove', methods=['POST'])
@authorized_personnel_only
def mail_users_remove():
	res = remove_mail_user(request.form.get('email', ''), env)
	if not isinstance(res, tuple):
		audit.log_admin_action(request.user_email, "user_remove", request.form.get('email', ''), None, env)
	return res


@app.route('/mail/users/privileges')
@authorized_personnel_only
def mail_user_privs():
	privs = get_mail_user_privileges(request.args.get('email', ''), env)
	if isinstance(privs, tuple): return privs # error
	return "\n".join(privs)

@app.route('/mail/users/privileges/add', methods=['POST'])
@authorized_personnel_only
def mail_user_privs_add():
	res = add_remove_mail_user_privilege(request.form.get('email', ''), request.form.get('privilege', ''), "add", env)
	if not isinstance(res, tuple):
		audit.log_admin_action(request.user_email, "user_privilege_add", request.form.get('email', ''), request.form.get('privilege', ''), env)
	return res

@app.route('/mail/users/privileges/remove', methods=['POST'])
@authorized_personnel_only
def mail_user_privs_remove():
	res = add_remove_mail_user_privilege(request.form.get('email', ''), request.form.get('privilege', ''), "remove", env)
	if not isinstance(res, tuple):
		audit.log_admin_action(request.user_email, "user_privilege_remove", request.form.get('email', ''), request.form.get('privilege', ''), env)
	return res


@app.route('/mail/aliases')
@authorized_personnel_only
def mail_aliases():
	if request.args.get("format", "") == "json":
		return json_response(get_mail_aliases_ex(env))
	return "".join(address+"\t"+receivers+"\t"+(senders or "")+"\n" for address, receivers, senders, auto in get_mail_aliases(env))

@app.route('/mail/aliases/add', methods=['POST'])
@authorized_personnel_only
def mail_aliases_add():
	res = add_mail_alias(
		request.form.get('address', ''),
		request.form.get('forwards_to', ''),
		request.form.get('permitted_senders', ''),
		env,
		update_if_exists=(request.form.get('update_if_exists', '') == '1')
		)
	if not isinstance(res, tuple):
		audit.log_admin_action(request.user_email, "alias_add", request.form.get('address', ''), f"forwards_to: {request.form.get('forwards_to', '')}, permitted_senders: {request.form.get('permitted_senders', '')}", env)
	return res

@app.route('/mail/aliases/remove', methods=['POST'])
@authorized_personnel_only
def mail_aliases_remove():
	res = remove_mail_alias(request.form.get('address', ''), env)
	if not isinstance(res, tuple):
		audit.log_admin_action(request.user_email, "alias_remove", request.form.get('address', ''), None, env)
	return res

@app.route('/mail/domains')
@authorized_personnel_only
def mail_domains():
    return "".join(x+"\n" for x in get_mail_domains(env))

# SPAM & FILTERING

@app.route('/spam/settings')
@authorized_personnel_only
def spam_get_settings():
	return json_response(get_spam_config(env))

@app.route('/spam/settings', methods=['POST'])
@authorized_personnel_only
def spam_set_settings():
	try:
		res = set_spam_config(env,
			threshold=request.form.get('spamassassin_threshold'),
			greylisting_enabled=request.form.get('greylisting_enabled'),
			greylisting_delay=request.form.get('greylisting_delay'),
			spamhaus_dqs_key=request.form.get('spamhaus_dqs_key'),
			spamhaus_zen=request.form.get('spamhaus_zen_enabled'),
			spamhaus_dbl=request.form.get('spamhaus_dbl_enabled'),
			spamhaus_zrd=request.form.get('spamhaus_zrd_enabled'),
		)
		details = f"threshold: {request.form.get('spamassassin_threshold')}, greylisting_enabled: {request.form.get('greylisting_enabled')}, greylisting_delay: {request.form.get('greylisting_delay')}"
		audit.log_admin_action(request.user_email, "spam_settings_change", None, details, env)
		return res
	except ValueError as e:
		return (str(e), 400)

@app.route('/spam/lists')
@authorized_personnel_only
def spam_get_lists():
	return json_response(get_spam_lists(env))

@app.route('/spam/lists/spamassassin-whitelist/add', methods=['POST'])
@authorized_personnel_only
def spam_sa_whitelist_add():
	try:
		res = add_spamassassin_whitelist(request.form.get('entry', ''), env)
		audit.log_admin_action(request.user_email, "spam_whitelist_add", request.form.get('entry', ''), None, env)
		return res
	except ValueError as e:
		return (str(e), 400)

@app.route('/spam/lists/spamassassin-whitelist/remove', methods=['POST'])
@authorized_personnel_only
def spam_sa_whitelist_remove():
	try:
		res = remove_spamassassin_whitelist(request.form.get('entry', ''), env)
		audit.log_admin_action(request.user_email, "spam_whitelist_remove", request.form.get('entry', ''), None, env)
		return res
	except ValueError as e:
		return (str(e), 400)

@app.route('/spam/lists/spamassassin-blacklist/add', methods=['POST'])
@authorized_personnel_only
def spam_sa_blacklist_add():
	try:
		res = add_spamassassin_blacklist(request.form.get('entry', ''), env)
		audit.log_admin_action(request.user_email, "spam_blacklist_add", request.form.get('entry', ''), None, env)
		return res
	except ValueError as e:
		return (str(e), 400)

@app.route('/spam/lists/spamassassin-blacklist/remove', methods=['POST'])
@authorized_personnel_only
def spam_sa_blacklist_remove():
	try:
		res = remove_spamassassin_blacklist(request.form.get('entry', ''), env)
		audit.log_admin_action(request.user_email, "spam_blacklist_remove", request.form.get('entry', ''), None, env)
		return res
	except ValueError as e:
		return (str(e), 400)

@app.route('/spam/lists/postgrey-whitelist/add', methods=['POST'])
@authorized_personnel_only
def spam_postgrey_whitelist_add():
	try:
		res = add_postgrey_whitelist(request.form.get('entry', ''), env)
		audit.log_admin_action(request.user_email, "spam_postgrey_add", request.form.get('entry', ''), None, env)
		return res
	except ValueError as e:
		return (str(e), 400)

@app.route('/spam/lists/postgrey-whitelist/remove', methods=['POST'])
@authorized_personnel_only
def spam_postgrey_whitelist_remove():
	try:
		res = remove_postgrey_whitelist(request.form.get('entry', ''), env)
		audit.log_admin_action(request.user_email, "spam_postgrey_remove", request.form.get('entry', ''), None, env)
		return res
	except ValueError as e:
		return (str(e), 400)

@app.route('/spam/lists/postfix-blocked/add', methods=['POST'])
@authorized_personnel_only
def spam_postfix_blocked_add():
	try:
		res = add_postfix_blocked_sender(request.form.get('entry', ''), env)
		audit.log_admin_action(request.user_email, "spam_blocked_add", request.form.get('entry', ''), None, env)
		return res
	except ValueError as e:
		return (str(e), 400)

@app.route('/spam/lists/postfix-blocked/remove', methods=['POST'])
@authorized_personnel_only
def spam_postfix_blocked_remove():
	try:
		res = remove_postfix_blocked_sender(request.form.get('entry', ''), env)
		audit.log_admin_action(request.user_email, "spam_blocked_remove", request.form.get('entry', ''), None, env)
		return res
	except ValueError as e:
		return (str(e), 400)

# DNS

@app.route('/dns/zones')
@authorized_personnel_only
def dns_zones():
	from dns_update import get_dns_zones
	return json_response([z[0] for z in get_dns_zones(env)])

@app.route('/dns/update', methods=['POST'])
@authorized_personnel_only
def dns_update():
	from dns_update import do_dns_update
	try:
		res = do_dns_update(env, force=request.form.get('force', '') == '1')
		if not (isinstance(res, tuple) and len(res) > 1 and isinstance(res[1], int) and res[1] >= 400):
			audit.log_admin_action(request.user_email, "dns_update", None, f"force: {request.form.get('force', '')}", env)
		return res
	except Exception as e:
		return (str(e), 500)

@app.route('/dns/secondary-nameserver')
@authorized_personnel_only
def dns_get_secondary_nameserver():
	from dns_update import get_custom_dns_config, get_secondary_dns
	return json_response({ "hostnames": get_secondary_dns(get_custom_dns_config(env), mode=None) })

@app.route('/dns/secondary-nameserver', methods=['POST'])
@authorized_personnel_only
def dns_set_secondary_nameserver():
	from dns_update import set_secondary_dns
	try:
		res = set_secondary_dns([ns.strip() for ns in re.split(r"[, ]+", request.form.get('hostnames') or "") if ns.strip() != ""], env)
		if not isinstance(res, tuple):
			audit.log_admin_action(request.user_email, "dns_secondary_ns_change", None, f"hostnames: {request.form.get('hostnames', '')}", env)
		return res
	except ValueError as e:
		return (str(e), 400)

@app.route('/dns/custom')
@authorized_personnel_only
def dns_get_records(qname=None, rtype=None):
	# Get the current set of custom DNS records.
	from dns_update import get_custom_dns_config, get_dns_zones
	records = get_custom_dns_config(env, only_real_records=True)

	# Filter per the arguments for the more complex GET routes below.
	records = [r for r in records
		if (not qname or r[0] == qname)
		and (not rtype or r[1] == rtype) ]

	# Make a better data structure.
	records = [
        {
                "qname": r[0],
                "rtype": r[1],
                "value": r[2],
		"sort-order": { },
        } for r in records ]

	# To help with grouping by zone in qname sorting, label each record with which zone it is in.
	# There's an inconsistency in how we handle zones in get_dns_zones and in sort_domains, so
	# do this first before sorting the domains within the zones.
	zones = utils.sort_domains([z[0] for z in get_dns_zones(env)], env)
	for r in records:
		for z in zones:
			if r["qname"] == z or r["qname"].endswith("." + z):
				r["zone"] = z
				break

	# Add sorting information. The 'created' order follows the order in the YAML file on disk,
	# which tracs the order entries were added in the control panel since we append to the end.
	# The 'qname' sort order sorts by our standard domain name sort (by zone then by qname),
	# then by rtype, and last by the original order in the YAML file (since sorting by value
	# may not make sense, unless we parse IP addresses, for example).
	for i, r in enumerate(records):
		r["sort-order"]["created"] = i
	domain_sort_order = utils.sort_domains([r["qname"] for r in records], env)
	for i, r in enumerate(sorted(records, key = lambda r : (
			zones.index(r["zone"]) if r.get("zone") else 0, # record is not within a zone managed by the box
			domain_sort_order.index(r["qname"]),
			r["rtype"]))):
		r["sort-order"]["qname"] = i

	# Return.
	return json_response(records)

@app.route('/dns/custom/<qname>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/dns/custom/<qname>/<rtype>', methods=['GET', 'POST', 'PUT', 'DELETE'])
@authorized_personnel_only
def dns_set_record(qname, rtype="A"):
	from dns_update import do_dns_update, set_custom_dns_record
	try:
		# Normalize.
		rtype = rtype.upper()

		# Read the record value from the request BODY, which must be
		# ASCII-only. Not used with GET.
		value = request.stream.read().decode("ascii", "ignore").strip()

		if request.method == "GET":
			# Get the existing records matching the qname and rtype.
			return dns_get_records(qname, rtype)

		if request.method in {"POST", "PUT"}:
			# There is a default value for A/AAAA records.
			if rtype in {"A", "AAAA"} and value == "":
				value = request.environ.get("HTTP_X_FORWARDED_FOR") # normally REMOTE_ADDR but we're behind nginx as a reverse proxy

			# Cannot add empty records.
			if value == '':
				return ("No value for the record provided.", 400)

			if request.method == "POST":
				# Add a new record (in addition to any existing records
				# for this qname-rtype pair).
				action = "add"
			elif request.method == "PUT":
				# In REST, PUT is supposed to be idempotent, so we'll
				# make this action set (replace all records for this
				# qname-rtype pair) rather than add (add a new record).
				action = "set"

		elif request.method == "DELETE":
			if value == '':
				# Delete all records for this qname-type pair.
				value = None
			else:
				# Delete just the qname-rtype-value record exactly.
				pass
			action = "remove"

		if set_custom_dns_record(qname, rtype, value, action, env):
			res = do_dns_update(env) or "Something isn't right."
		else:
			res = "OK"

		if not (isinstance(res, tuple) and len(res) > 1 and isinstance(res[1], int) and res[1] >= 400) and res != "Something isn't right.":
			audit_action = "dns_custom_remove" if action == "remove" else "dns_custom_add"
			details = f"rtype: {rtype}, value: {value or ''}"
			audit.log_admin_action(request.user_email, audit_action, qname, details, env)
		return res

	except ValueError as e:
		return (str(e), 400)

@app.route('/dns/dump')
@authorized_personnel_only
def dns_get_dump():
	from dns_update import build_recommended_dns
	return json_response(build_recommended_dns(env))

@app.route('/dns/zonefile/<zone>')
@authorized_personnel_only
def dns_get_zonefile(zone):
	from dns_update import get_dns_zonefile
	return Response(get_dns_zonefile(zone, env), status=200, mimetype='text/plain')

# SSL

@app.route('/ssl/status')
@authorized_personnel_only
def ssl_get_status():
	from ssl_certificates import get_certificates_to_provision
	from web_update import get_web_domains_info, get_web_domains

	# What domains can we provision certificates for? What unexpected problems do we have?
	provision, cant_provision = get_certificates_to_provision(env, show_valid_certs=False)

	# What's the current status of TLS certificates on all of the domain?
	domains_status = get_web_domains_info(env)
	domains_status = [
		{
			"domain": d["domain"],
			"status": d["ssl_certificate"][0],
			"text": d["ssl_certificate"][1] + (" " + cant_provision[d["domain"]] if d["domain"] in cant_provision else "")
		} for d in domains_status ]

	# Warn the user about domain names not hosted here because of other settings.
	for domain in set(get_web_domains(env, exclude_dns_elsewhere=False)) - set(get_web_domains(env)):
		domains_status.append({
			"domain": domain,
			"status": "not-applicable",
			"text": "The domain's website is hosted elsewhere.",
		})

	return json_response({
		"can_provision": utils.sort_domains(provision, env),
		"status": domains_status,
	})

@app.route('/ssl/csr/<domain>', methods=['POST'])
@authorized_personnel_only
def ssl_get_csr(domain):
	from ssl_certificates import create_csr
	ssl_private_key = os.path.join(os.path.join(env["STORAGE_ROOT"], 'ssl', 'ssl_private_key.pem'))
	res = create_csr(domain, ssl_private_key, request.form.get('countrycode', ''), env)
	if not isinstance(res, tuple):
		audit.log_admin_action(request.user_email, "ssl_csr_generate", domain, f"countrycode: {request.form.get('countrycode', '')}", env)
	return res

@app.route('/ssl/install', methods=['POST'])
@authorized_personnel_only
def ssl_install_cert():
	from web_update import get_web_domains
	from ssl_certificates import install_cert
	domain = request.form.get('domain')
	ssl_cert = request.form.get('cert')
	ssl_chain = request.form.get('chain')
	if domain not in get_web_domains(env):
		return "Invalid domain name."
	res = install_cert(domain, ssl_cert, ssl_chain, env)
	if not isinstance(res, tuple) and not res.startswith("Invalid"):
		audit.log_admin_action(request.user_email, "ssl_install", domain, None, env)
	return res

@app.route('/ssl/provision', methods=['POST'])
@authorized_personnel_only
def ssl_provision_certs():
	from ssl_certificates import provision_certificates
	requests = provision_certificates(env, limit_domains=None)
	audit.log_admin_action(request.user_email, "ssl_provision", None, None, env)
	return json_response({ "requests": requests })

# multi-factor auth

@app.route('/mfa/status', methods=['POST'])
@authorized_personnel_only
def mfa_get_status():
	# Anyone accessing this route is an admin, and we permit them to
	# see the MFA status for any user if they submit a 'user' form
	# field. But we don't include provisioning info since a user can
	# only provision for themselves.
	email = request.form.get('user', request.user_email) # user field if given, otherwise the user making the request
	try:
		resp = {
			"enabled_mfa": get_public_mfa_state(email, env)
		}
		if email == request.user_email:
			resp.update({
				"new_mfa": {
					"totp": provision_totp(email, env)
				}
			})
	except ValueError as e:
		return (str(e), 400)
	return json_response(resp)

@app.route('/mfa/webauthn/register/begin', methods=['POST'])
@authorized_personnel_only
def mfa_webauthn_register_begin():
	try:
		email = request.user_email
		options = provision_webauthn(email, env, auth_service)
		return json_response(options)
	except ValueError as e:
		return (str(e), 400)

@app.route('/mfa/webauthn/register/complete', methods=['POST'])
@authorized_personnel_only
def mfa_webauthn_register_complete():
	try:
		email = request.user_email
		response_data = json.loads(request.form.get("response_data", "{}"))
		label = request.form.get("label", "Security Key")
		recovery_codes = register_webauthn(email, response_data, label, env, auth_service)
		audit.log_admin_action(request.user_email, "mfa_enable", email, f"webauthn: {label}", env)
		return json_response({
			"status": "ok",
			"recovery_codes": recovery_codes
		})
	except ValueError as e:
		return (str(e), 400)

@app.route('/mfa/totp/enable', methods=['POST'])
@authorized_personnel_only
def totp_post_enable():
	secret = request.form.get('secret')
	token = request.form.get('token')
	label = request.form.get('label')
	if not isinstance(token, str):
		return ("Bad Input", 400)
	try:
		validate_totp_secret(secret)
		recovery_codes = enable_mfa(request.user_email, "totp", secret, token, label, env)
		audit.log_admin_action(request.user_email, "mfa_enable", request.user_email, f"totp: {label}", env)
		return json_response({
			"status": "ok",
			"recovery_codes": recovery_codes
		})
	except ValueError as e:
		return (str(e), 400)

@app.route('/mfa/disable', methods=['POST'])
@authorized_personnel_only
def totp_post_disable():
	# Anyone accessing this route is an admin, and we permit them to
	# disable the MFA status for any user if they submit a 'user' form
	# field.
	email = request.form.get('user', request.user_email) # user field if given, otherwise the user making the request
	try:
		result = disable_mfa(email, request.form.get('mfa-id') or None, env) # convert empty string to None
	except ValueError as e:
		return (str(e), 400)
	if result: # success
		audit.log_admin_action(request.user_email, "mfa_disable", email, f"mfa-id: {request.form.get('mfa-id') or 'all'}", env)
		return "OK"
	# error
	return ("Invalid user or MFA id.", 400)

# WEB

@app.route('/web/domains')
@authorized_personnel_only
def web_get_domains():
	from web_update import get_web_domains_info
	return json_response(get_web_domains_info(env))

@app.route('/web/update', methods=['POST'])
@authorized_personnel_only
def web_update():
	from web_update import do_web_update
	res = do_web_update(env)
	if not isinstance(res, tuple):
		audit.log_admin_action(request.user_email, "web_update", None, None, env)
	return res

# System

@app.route('/system/version', methods=["GET"])
@authorized_personnel_only
def system_version():
	from status_checks import what_version_is_this
	try:
		return what_version_is_this(env)
	except Exception as e:
		return (str(e), 500)

@app.route('/system/latest-upstream-version', methods=["POST"])
@authorized_personnel_only
def system_latest_upstream_version():
	from status_checks import get_latest_miab_version
	try:
		return get_latest_miab_version()
	except Exception as e:
		return (str(e), 500)

@app.route('/system/status', methods=["POST"])
@authorized_personnel_only
def system_status():
	from status_checks import run_checks
	class WebOutput:
		def __init__(self):
			self.items = []
		def add_heading(self, heading):
			self.items.append({ "type": "heading", "text": heading, "extra": [] })
		def print_ok(self, message):
			self.items.append({ "type": "ok", "text": message, "extra": [] })
		def print_error(self, message):
			self.items.append({ "type": "error", "text": message, "extra": [] })
		def print_warning(self, message):
			self.items.append({ "type": "warning", "text": message, "extra": [] })
		def print_line(self, message, monospace=False):
			self.items[-1]["extra"].append({ "text": message, "monospace": monospace })
	output = WebOutput()
	# Create a temporary pool of processes for the status checks
	with multiprocessing.pool.Pool(processes=5) as pool:
		run_checks(False, env, output, pool)
		pool.close()
		pool.join()
	return json_response(output.items)

@app.route('/system/updates')
@authorized_personnel_only
def show_updates():
	from status_checks import list_apt_updates
	return "".join(
		"{} ({})\n".format(p["package"], p["version"])
		for p in list_apt_updates())

@app.route('/system/update-packages', methods=["POST"])
@authorized_personnel_only
def do_updates():
	utils.shell("check_call", ["/usr/bin/apt-get", "-qq", "update"])
	res = utils.shell("check_output", ["/usr/bin/apt-get", "-y", "upgrade"], env={
		"DEBIAN_FRONTEND": "noninteractive"
	})
	audit.log_admin_action(request.user_email, "system_update_packages", None, None, env)
	return res


@app.route('/system/reboot', methods=["GET"])
@authorized_personnel_only
def needs_reboot():
	from status_checks import is_reboot_needed_due_to_package_installation
	if is_reboot_needed_due_to_package_installation():
		return json_response(True)
	return json_response(False)

@app.route('/system/reboot', methods=["POST"])
@authorized_personnel_only
def do_reboot():
	# To keep the attack surface low, we don't allow a remote reboot if one isn't necessary.
	from status_checks import is_reboot_needed_due_to_package_installation
	if is_reboot_needed_due_to_package_installation():
		res = utils.shell("check_output", ["/sbin/shutdown", "-r", "now"], capture_stderr=True)
		audit.log_admin_action(request.user_email, "system_reboot", None, None, env)
		return res
	return "No reboot is required, so it is not allowed."


@app.route('/system/backup/status')
@authorized_personnel_only
def backup_status():
	from backup import backup_status
	try:
		return json_response(backup_status(env))
	except Exception as e:
		return json_response({ "error": str(e) })

@app.route('/system/backup/config', methods=["GET"])
@authorized_personnel_only
def backup_get_custom():
	from backup import get_backup_config
	return json_response(get_backup_config(env, for_ui=True))

@app.route('/system/backup/config', methods=["POST"])
@authorized_personnel_only
def backup_set_custom():
	from backup import backup_set_custom
	res = backup_set_custom(env,
		request.form.get('target', ''),
		request.form.get('target_user', ''),
		request.form.get('target_pass', ''),
		request.form.get('min_age', '')
	)
	if not (isinstance(res, tuple) and len(res) > 1 and isinstance(res[1], int) and res[1] >= 400) and not (isinstance(res, dict) and "error" in res):
		audit.log_admin_action(request.user_email, "system_backup_config", request.form.get('target'), f"min_age: {request.form.get('min_age')}", env)
	return json_response(res)

@app.route('/system/backup/test-config', methods=["POST"])
@authorized_personnel_only
def backup_test_config():
	from backup import list_target_files
	target = request.form.get('target', '')
	target_user = request.form.get('target_user', '')
	target_pass = request.form.get('target_pass', '')

	config = {
		"target": target,
		"target_user": target_user,
		"target_pass": target_pass,
	}

	try:
		if target in {"off", "local"}:
			return json_response({ "status": "ok", "message": "Connection test not needed for local/disabled backup." })
		
		# list_target_files raises ValueError or Exception on failure, returns list on success
		list_target_files(config)
		return json_response({ "status": "ok" })
	except Exception as e:
		return json_response({ "status": "error", "message": str(e) })

@app.route('/system/privacy', methods=["GET"])
@authorized_personnel_only
def privacy_status_get():
	config = utils.load_settings(env)
	return json_response(config.get("privacy", True))

@app.route('/system/privacy', methods=["POST"])
@authorized_personnel_only
def privacy_status_set():
	config = utils.load_settings(env)
	val = request.form.get('value')
	config["privacy"] = (val == "private")
	utils.write_settings(config, env)
	audit.log_admin_action(request.user_email, "system_privacy_change", val, None, env)
	return "OK"

@app.route('/system/services/postfix', methods=["GET"])
@authorized_personnel_only
def get_system_services_postfix():
	inet_protocols = utils.shell("check_output", ["postconf", "-h", "inet_protocols"]).strip()
	try:
		smtp_address_preference = utils.shell("check_output", ["postconf", "-h", "smtp_address_preference"], trap=True)[1].strip()
		if not smtp_address_preference:
			smtp_address_preference = 'any'
	except Exception:
		smtp_address_preference = 'any'
	return json_response({ "inet_protocols": inet_protocols, "smtp_address_preference": smtp_address_preference })

@app.route('/system/services/postfix', methods=["POST"])
@authorized_personnel_only
def set_system_services_postfix():
	inet_protocols = request.form.get('inet_protocols')
	smtp_address_preference = request.form.get('smtp_address_preference')
	
	if inet_protocols not in ('all', 'ipv4', 'ipv6'):
		return ("Invalid value for inet_protocols", 400)
	if smtp_address_preference not in ('any', 'ipv4', 'ipv6'):
		return ("Invalid value for smtp_address_preference", 400)
		
	try:
		utils.shell("check_call", ["postconf", "-e", f"inet_protocols = {inet_protocols}"])
		utils.shell("check_call", ["postconf", "-e", f"smtp_address_preference = {smtp_address_preference}"])
		utils.shell("check_call", ["service", "postfix", "restart"])
		audit.log_admin_action(request.user_email, "system_postfix_config", None, f"inet_protocols: {inet_protocols}, smtp_address_preference: {smtp_address_preference}", env)
	except Exception as e:
		return (str(e), 500)
	return "OK"

# MUNIN

@app.route('/munin/')
@authorized_personnel_only
def munin_start():
	# Munin pages, static images, and dynamically generated images are served
	# outside of the AJAX API. We'll start with a 'start' API that sets a cookie
	# that subsequent requests will read for authorization. (We don't use cookies
	# for the API to avoid CSRF vulnerabilities.)
	response = make_response("OK")
	response.set_cookie("session", auth_service.create_session_key(request.user_email, env, type='cookie'),
	    max_age=60*30, secure=True, httponly=True, samesite="Strict") # 30 minute duration
	return response

def check_request_cookie_for_admin_access():
	session = auth_service.get_session(None, request.cookies.get("session", ""), "cookie", env)
	if not session: return False
	privs = get_mail_user_privileges(session["email"], env)
	if not isinstance(privs, list): return False
	return "admin" in privs

def authorized_personnel_only_via_cookie(f):
	@wraps(f)
	def g(*args, **kwargs):
		if not check_request_cookie_for_admin_access():
			return Response("Unauthorized", status=403, mimetype='text/plain', headers={})
		return f(*args, **kwargs)
	return g

@app.route('/munin/<path:filename>')
@authorized_personnel_only_via_cookie
def munin_static_file(filename=""):
	# Proxy the request to static files.
	if filename == "": filename = "index.html"
	return send_from_directory("/var/cache/munin/www", filename)

@app.route('/munin/cgi-graph/<path:filename>')
@authorized_personnel_only_via_cookie
def munin_cgi(filename):
	""" Relay munin cgi dynazoom requests
	/usr/lib/munin/cgi/munin-cgi-graph is a perl cgi script in the munin package
	that is responsible for generating binary png images _and_ associated HTTP
	headers based on parameters in the requesting URL. All output is written
	to stdout which munin_cgi splits into response headers and binary response
	data.
	munin-cgi-graph reads environment variables to determine
	what it should do. It expects a path to be in the env-var PATH_INFO, and a
	querystring to be in the env-var QUERY_STRING.
	munin-cgi-graph has several failure modes. Some write HTTP Status headers and
	others return nonzero exit codes.
	Situating munin_cgi between the user-agent and munin-cgi-graph enables keeping
	the cgi script behind mailinabox's auth mechanisms and avoids additional
	support infrastructure like spawn-fcgi.
	"""

	COMMAND = 'su munin --preserve-environment --shell=/bin/bash -c /usr/lib/munin/cgi/munin-cgi-graph'
	# su changes user, we use the munin user here
	# --preserve-environment retains the environment, which is where Popen's `env` data is
	# --shell=/bin/bash ensures the shell used is bash
	# -c "/usr/lib/munin/cgi/munin-cgi-graph" passes the command to run as munin
	# "%s" is a placeholder for where the request's querystring will be added

	if filename == "":
		return ("a path must be specified", 404)

	query_str = request.query_string.decode("utf-8", 'ignore')

	env = {'PATH_INFO': f'/{filename}/', 'REQUEST_METHOD': 'GET', 'QUERY_STRING': query_str}
	code, binout = utils.shell('check_output',
							   COMMAND.split(" ", 5),
							   # Using a maxsplit of 5 keeps the last arguments together
							   env=env,
							   return_bytes=True,
							   trap=True)

	if code != 0:
		# nonzero returncode indicates error
		app.logger.error("munin_cgi: munin-cgi-graph returned nonzero exit code, %s", code)
		return ("error processing graph image", 500)

	# /usr/lib/munin/cgi/munin-cgi-graph returns both headers and binary png when successful.
	# A double-Windows-style-newline always indicates the end of HTTP headers.
	headers, image_bytes = binout.split(b'\r\n\r\n', 1)
	response = make_response(image_bytes)
	for line in headers.splitlines():
		name, value = line.decode("utf8").split(':', 1)
		response.headers[name] = value
	if 'Status' in response.headers and '404' in response.headers['Status']:
		app.logger.warning("munin_cgi: munin-cgi-graph returned 404 status code. PATH_INFO=%s", env['PATH_INFO'])
	return response

def log_failed_login(request):
	# We need to figure out the ip to list in the message, all our calls are routed
	# through nginx who will put the original ip in X-Forwarded-For.
	# During setup we call the management interface directly to determine the user
	# status. So we can't always use X-Forwarded-For because during setup that header
	# will not be present.
	ip = request.headers.getlist("X-Forwarded-For")[0] if request.headers.getlist("X-Forwarded-For") else request.remote_addr

	# We need to add a timestamp to the log message, otherwise /dev/log will eat the "duplicate"
	# message.
	app.logger.warning("Mail-in-a-Box Management Daemon: Failed login attempt from ip %s - timestamp %s", ip, time.time())


# Custom CSS serving route
@app.route('/custom.css')
def custom_css():
	return send_from_directory(os.path.join(os.path.dirname(me), "templates"), "custom.css", mimetype="text/css")

# Realtime system metrics (CPU, Memory, Disk, Mail Queue)
@app.route('/system/metrics/realtime', methods=["GET"])
@authorized_personnel_only
def system_metrics_realtime():
	import psutil
	try:
		# Calculate mail queue size
		queue_size = 0
		try:
			code, output = utils.shell("check_output", ["postqueue", "-p"], trap=True)
			output = output.strip()
			if "Mail queue is empty" in output:
				queue_size = 0
			else:
				lines = output.splitlines()
				if len(lines) > 0 and lines[-1].startswith("--"):
					m = re.search(r"in\s+(\d+)\s+Requests", lines[-1])
					if m:
						queue_size = int(m.group(1))
		except Exception:
			pass

		# CPU usage percent
		cpu_pct = psutil.cpu_percent(interval=None)

		# Memory usage
		mem = psutil.virtual_memory()
		mem_data = {
			"percent": mem.percent,
			"used": mem.used,
			"total": mem.total
		}

		# Disk usage (check storage root)
		storage_root = env.get("STORAGE_ROOT", "/")
		disk = psutil.disk_usage(storage_root)
		disk_data = {
			"percent": disk.percent,
			"used": disk.used,
			"total": disk.total
		}

		# Services status (active/inactive)
		services = ["nginx", "postfix", "dovecot", "fail2ban", "opendkim", "spampd"]
		services_status = {}
		for service in services:
			try:
				# systemctl is-active service
				code, _ = utils.shell("check_output", ["systemctl", "is-active", service], trap=True)
				services_status[service] = "active" if code == 0 else "inactive"
			except Exception:
				services_status[service] = "unknown"

		return json_response({
			"cpu": cpu_pct,
			"ram": mem_data,
			"disk": disk_data,
			"mail_queue": queue_size,
			"services": services_status
		})
	except Exception as e:
		return (str(e), 500)

# Recursive helper to convert set, datetime objects to JSON-serializable types
def make_json_safe(o):
	if isinstance(o, (datetime.datetime, datetime.date)):
		return o.isoformat()
	elif isinstance(o, (set, frozenset)):
		return list(o)
	elif isinstance(o, dict):
		processed_dict = {}
		for k, v in o.items():
			if isinstance(k, tuple):
				new_key = "/".join(str(item) for item in k)
			elif isinstance(k, (datetime.datetime, datetime.date)):
				new_key = k.isoformat()
			elif not isinstance(k, (str, int, float, bool)) and k is not None:
				new_key = str(k)
			else:
				new_key = k
			processed_dict[new_key] = make_json_safe(v)
		return processed_dict
	elif isinstance(o, list):
		return [make_json_safe(v) for v in o]
	elif isinstance(o, tuple):
		return tuple(make_json_safe(v) for v in o)
	return o

class SilenceStdout:
	def __enter__(self):
		self._original_stdout = sys.stdout
		sys.stdout = open(os.devnull, 'w')
	def __exit__(self, exc_type, exc_val, exc_tb):
		sys.stdout.close()
		sys.stdout = self._original_stdout

# System email stats
@app.route('/mail/stats', methods=["GET"])
@authorized_personnel_only
def mail_stats_api():
	import mail_log
	# Reset/configure globals in mail_log
	mail_log.END_DATE = datetime.datetime.now()
	mail_log.NOW = mail_log.END_DATE
	timespan = request.args.get('timespan', 'today')
	if timespan not in mail_log.TIME_DELTAS:
		timespan = 'today'
	mail_log.START_DATE = mail_log.END_DATE - mail_log.TIME_DELTAS[timespan]
	mail_log.SCAN_IN = True
	mail_log.SCAN_OUT = True
	mail_log.SCAN_DOVECOT_LOGIN = True
	mail_log.SCAN_GREY = True
	mail_log.SCAN_BLOCKED = True
	mail_log.FILTERS = None
	mail_log.VERBOSE = False

	try:
		with SilenceStdout():
			collector = mail_log.scan_mail_log(env)
		if collector is None:
			# No log lines were found for the given time range
			collector = {
				"sent_mail": {},
				"received_mail": {},
				"logins": {},
				"postgrey": {},
				"rejected": {},
			}
		return json_response(make_json_safe(collector))
	except Exception as e:
		return (str(e), 500)

# Fail2ban client helpers
def get_fail2ban_status():
	code, output = utils.shell("check_output", ["fail2ban-client", "status"], trap=True)
	if code != 0:
		return {"enabled": False, "jails": []}
	m = re.search(r"Jail list:\s+(.*)", output)
	if m:
		jails = [j.strip() for j in m.group(1).split(",") if j.strip()]
		return {"enabled": True, "jails": jails}
	return {"enabled": True, "jails": []}

def get_fail2ban_jail_status(jail):
	if not re.match(r"^[a-zA-Z0-9_-]+$", jail):
		raise ValueError("Invalid jail name")
	code, output = utils.shell("check_output", ["fail2ban-client", "status", jail], trap=True)
	if code != 0:
		return None
	
	currently_failed = 0
	total_failed = 0
	currently_banned = 0
	total_banned = 0
	banned_ips = []
	
	m = re.search(r"Currently failed:\s+(\d+)", output)
	if m: currently_failed = int(m.group(1))
	
	m = re.search(r"Total failed:\s+(\d+)", output)
	if m: total_failed = int(m.group(1))
	
	m = re.search(r"Currently banned:\s+(\d+)", output)
	if m: currently_banned = int(m.group(1))
	
	m = re.search(r"Total banned:\s+(\d+)", output)
	if m: total_banned = int(m.group(1))
	
	m = re.search(r"Banned IP list:\s+(.*)", output)
	if m:
		banned_ips = [ip.strip() for ip in m.group(1).split() if ip.strip()]
		
	return {
		"jail": jail,
		"currently_failed": currently_failed,
		"total_failed": total_failed,
		"currently_banned": currently_banned,
		"total_banned": total_banned,
		"banned_ips": banned_ips
	}

# Fail2ban Endpoints
@app.route('/system/fail2ban/status', methods=['GET'])
@authorized_personnel_only
def fail2ban_status_api():
	try:
		status = get_fail2ban_status()
		if not status["enabled"]:
			return json_response(status)
		
		jails_detail = []
		for jail in status["jails"]:
			detail = get_fail2ban_jail_status(jail)
			if detail:
				jails_detail.append(detail)
		return json_response({
			"enabled": True,
			"jails": jails_detail
		})
	except Exception as e:
		return (str(e), 500)

@app.route('/system/fail2ban/jail/<jail>/unban', methods=['POST'])
@authorized_personnel_only
def fail2ban_unban_api(jail):
	if not re.match(r"^[a-zA-Z0-9_-]+$", jail):
		return ("Invalid jail name", 400)
	ip = request.form.get('ip')
	if not ip:
		return ("IP address required", 400)
	if not re.match(r"^[a-fA-F0-9.:]+$", ip):
		return ("Invalid IP address format", 400)
	
	try:
		utils.shell("check_call", ["fail2ban-client", "set", jail, "unbanip", ip])
		audit.log_admin_action(request.user_email, "f2b_unban", ip, jail, env)
		return "OK"
	except Exception as e:
		return (str(e), 500)

@app.route('/system/fail2ban/jail/<jail>/ban', methods=['POST'])
@authorized_personnel_only
def fail2ban_ban_api(jail):
	if not re.match(r"^[a-zA-Z0-9_-]+$", jail):
		return ("Invalid jail name", 400)
	ip = request.form.get('ip')
	if not ip:
		return ("IP address required", 400)
	if not re.match(r"^[a-fA-F0-9.:]+$", ip):
		return ("Invalid IP address format", 400)
	
	try:
		utils.shell("check_call", ["fail2ban-client", "set", jail, "banip", ip])
		audit.log_admin_action(request.user_email, "f2b_ban", ip, jail, env)
		return "OK"
	except Exception as e:
		return (str(e), 500)

# System log viewer api
@app.route('/system/logs', methods=['GET'])
@authorized_personnel_only
def get_logs_api():
	log_type = request.args.get('log_type', 'mail')
	lines_limit = request.args.get('lines', '500')
	filter_query = request.args.get('filter', '').strip()
	use_regex = request.args.get('use_regex', 'false').lower() == 'true'
	case_sensitive = request.args.get('case_sensitive', 'false').lower() == 'true'
	
	log_paths = {
		'mail': '/var/log/mail.log',
		'syslog': '/var/log/syslog',
		'nginx_access': '/var/log/nginx/access.log',
		'nginx_error': '/var/log/nginx/error.log',
		'fail2ban': '/var/log/fail2ban.log'
	}
	
	if log_type not in log_paths:
		return ("Invalid log type", 400)
		
	path = log_paths[log_type]
	if not os.path.exists(path):
		return json_response({"lines": [], "message": f"Log file {path} does not exist."})
		
	try:
		lines_limit = int(lines_limit)
		lines_limit = min(max(10, lines_limit), 5000)
	except ValueError:
		lines_limit = 500
		
	try:
		if filter_query:
			# Build grep command for efficient direct search on the entire log file
			cmd = ["grep"]
			if use_regex:
				cmd.append("-E")
			else:
				cmd.append("-F")
			if not case_sensitive:
				cmd.append("-i")
			
			cmd.extend([filter_query, path])
			code, output = utils.shell("check_output", cmd, trap=True)
			
			# Grep exits with code 1 if no matches are found. This is normal, not an error.
			if code == 1:
				lines = []
			elif code != 0:
				raise Exception(f"Grep command failed with code {code}: {output}")
			else:
				lines = output.splitlines()
				if len(lines) > lines_limit:
					lines = lines[-lines_limit:]
		else:
			# Standard behavior: retrieve the tail of the log file
			code, output = utils.shell("check_output", ["tail", "-n", str(lines_limit), path], trap=True)
			if code != 0:
				raise Exception(f"Tail command failed with code {code}: {output}")
			lines = output.splitlines()
			
		return json_response({
			"log_type": log_type,
			"lines": lines
		})
	except Exception as e:
		return (str(e), 500)

# System Mail Queue API
@app.route('/system/mail-queue', methods=['GET'])
@authorized_personnel_only
def get_mail_queue_api():
	try:
		code, output = utils.shell("check_output", ["/usr/sbin/postqueue", "-j"], trap=True)
		if code != 0:
			code, output = utils.shell("check_output", ["postqueue", "-j"], trap=True)
		
		queue_items = []
		if code == 0 and output.strip():
			for line in output.strip().splitlines():
				if line.strip():
					try:
						queue_items.append(json.loads(line))
					except ValueError:
						pass
		return json_response(queue_items)
	except Exception as e:
		return (str(e), 500)

@app.route('/system/mail-queue/flush', methods=['POST'])
@authorized_personnel_only
def flush_mail_queue_api():
	try:
		code, output = utils.shell("check_output", ["/usr/sbin/postqueue", "-f"], trap=True)
		if code != 0:
			code, output = utils.shell("check_output", ["postqueue", "-f"], trap=True)
		audit.log_admin_action(request.user_email, "system_mail_queue_flush", None, None, env)
		return "OK"
	except Exception as e:
		return (str(e), 500)

@app.route('/system/mail-queue/delete', methods=['POST'])
@authorized_personnel_only
def delete_mail_queue_api():
	queue_id = request.form.get('queue_id')
	if not queue_id:
		return ("Queue ID required", 400)
	if not re.match(r"^[a-zA-Z0-9]+$", queue_id):
		return ("Invalid Queue ID format", 400)
	try:
		code, output = utils.shell("check_output", ["/usr/sbin/postsuper", "-d", queue_id], trap=True)
		if code != 0:
			code, output = utils.shell("check_output", ["postsuper", "-d", queue_id], trap=True)
		audit.log_admin_action(request.user_email, "system_mail_queue_delete", queue_id, None, env)
		return "OK"
	except Exception as e:
		return (str(e), 500)

# System Active Connections API
@app.route('/system/active-connections', methods=['GET'])
@authorized_personnel_only
def get_active_connections_api():
	try:
		web_sessions = []
		for token, session_info in auth_service.sessions.items():
			web_sessions.append({
				"email": session_info.get("email"),
				"type": session_info.get("type"),
				"token_masked": token[:8] + "..." + token[-8:] if token else ""
			})

		dovecot_connections = []
		code, output = utils.shell("check_output", ["/usr/bin/doveadm", "connection", "list"], trap=True)
		if code != 0:
			code, output = utils.shell("check_output", ["doveadm", "connection", "list"], trap=True)
		
		if code == 0:
			lines = output.strip().splitlines()
			if len(lines) > 1:
				header = lines[0].lower().split()
				for line in lines[1:]:
					parts = line.split()
					if len(parts) >= len(header):
						conn = dict(zip(header, parts))
						dovecot_connections.append(conn)
					else:
						dovecot_connections.append({"raw": line})
						
		return json_response({
			"web_sessions": web_sessions,
			"dovecot_connections": dovecot_connections
		})
	except Exception as e:
		return (str(e), 500)

# System Backup Stats API
@app.route('/system/backup/stats', methods=['GET'])
@authorized_personnel_only
def backup_stats_api():
	from backup import backup_status
	try:
		return json_response(backup_status(env))
	except Exception as e:
		return json_response({ "error": str(e) })

# System Spam & DMARC Analytics API
@app.route('/system/spam-dmarc/stats', methods=['GET'])
@authorized_personnel_only
def spam_dmarc_stats_api():
	dmarc_dir = os.path.join(env["STORAGE_ROOT"], "mail", "dmarc")
	max_dmarc_xml_bytes = 5 * 1024 * 1024
	
	dmarc_stats = {
		"total_messages": 0,
		"spf_pass": 0,
		"spf_fail": 0,
		"dkim_pass": 0,
		"dkim_fail": 0,
		"dispositions": {"none": 0, "quarantine": 0, "reject": 0},
		"by_source_ip": {},
		"by_domain": {},
		"reports_count": 0
	}
	
	if os.path.exists(dmarc_dir):
		import gzip, zipfile, glob
		try:
			from defusedxml import ElementTree as safe_et
		except Exception:
			import xml.etree.ElementTree as safe_et
		
		now = time.time()
		thirty_days_ago = now - 30 * 86400
		
		files = []
		for ext in ["*.xml", "*.xml.gz", "*.zip", "*.gz"]:
			files.extend(glob.glob(os.path.join(dmarc_dir, ext)))
			
		files = [f for f in files if os.path.getmtime(f) >= thirty_days_ago]
		
		for fpath in files:
			try:
				content = None
				if fpath.endswith(".gz") or fpath.endswith(".xml.gz"):
					with gzip.open(fpath, "rb") as f:
						content = f.read(max_dmarc_xml_bytes + 1)
				elif fpath.endswith(".zip"):
					with zipfile.ZipFile(fpath, "r") as z:
						for name in z.namelist():
							if name.endswith(".xml"):
								if z.getinfo(name).file_size > max_dmarc_xml_bytes:
									app.logger.warning("DMARC report %s skipped: XML payload exceeds size limit (%s bytes).", os.path.basename(fpath), max_dmarc_xml_bytes)
									continue
								content = z.read(name)
								break
				else:
					if os.path.getsize(fpath) > max_dmarc_xml_bytes:
						app.logger.warning("DMARC report %s skipped: XML payload exceeds size limit (%s bytes).", os.path.basename(fpath), max_dmarc_xml_bytes)
						continue
					with open(fpath, "rb") as f:
						content = f.read(max_dmarc_xml_bytes + 1)
						
				if not content:
					continue
				if len(content) > max_dmarc_xml_bytes:
					app.logger.warning("DMARC report %s skipped: XML payload exceeds size limit (%s bytes).", os.path.basename(fpath), max_dmarc_xml_bytes)
					continue
					
				root = safe_et.fromstring(content)
				dmarc_stats["reports_count"] += 1
				
				for record in root.findall(".//record"):
					count_el = record.find(".//row/count")
					count = int(count_el.text) if count_el is not None else 1
					
					dmarc_stats["total_messages"] += count
					
					policy = record.find(".//row/policy_evaluated")
					if policy is not None:
						disp_el = policy.find("disposition")
						if disp_el is not None:
							disp = disp_el.text
							dmarc_stats["dispositions"][disp] = dmarc_stats["dispositions"].get(disp, 0) + count
							
						dkim_el = policy.find("dkim")
						if dkim_el is not None:
							if dkim_el.text == "pass":
								dmarc_stats["dkim_pass"] += count
							else:
								dmarc_stats["dkim_fail"] += count
								
						spf_el = policy.find("spf")
						if spf_el is not None:
							if spf_el.text == "pass":
								dmarc_stats["spf_pass"] += count
							else:
								dmarc_stats["spf_fail"] += count
								
					src_ip_el = record.find(".//row/source_ip")
					if src_ip_el is not None:
						ip = src_ip_el.text
						dmarc_stats["by_source_ip"][ip] = dmarc_stats["by_source_ip"].get(ip, 0) + count
								
					hdr_from_el = record.find(".//identifiers/header_from")
					if hdr_from_el is not None:
						domain = hdr_from_el.text
						if domain not in dmarc_stats["by_domain"]:
							dmarc_stats["by_domain"][domain] = {"total": 0, "spf_pass": 0, "dkim_pass": 0}
						dmarc_stats["by_domain"][domain]["total"] += count
						if policy is not None:
							policy_spf = policy.find("spf")
							if policy_spf is not None and policy_spf.text == "pass":
								dmarc_stats["by_domain"][domain]["spf_pass"] += count
							policy_dkim = policy.find("dkim")
							if policy_dkim is not None and policy_dkim.text == "pass":
								dmarc_stats["by_domain"][domain]["dkim_pass"] += count
			except Exception as e:
				app.logger.warning("Failed to parse DMARC report %s: %s", os.path.basename(fpath), e)
				continue
				
	top_ips = sorted(dmarc_stats["by_source_ip"].items(), key=lambda x: x[1], reverse=True)[:10]
	dmarc_stats["top_source_ips"] = [{"ip": ip, "count": count} for ip, count in top_ips]
	
	if "by_source_ip" in dmarc_stats:
		del dmarc_stats["by_source_ip"]
		
	# Include spam block rates for the last 7 days
	import mail_log
	orig_end = getattr(mail_log, 'END_DATE', None)
	orig_now = getattr(mail_log, 'NOW', None)
	orig_start = getattr(mail_log, 'START_DATE', None)
	
	mail_log.END_DATE = datetime.datetime.now()
	mail_log.NOW = mail_log.END_DATE
	mail_log.START_DATE = mail_log.END_DATE - datetime.timedelta(days=7)
	mail_log.SCAN_IN = True
	mail_log.SCAN_OUT = False
	mail_log.SCAN_DOVECOT_LOGIN = False
	mail_log.SCAN_GREY = False
	mail_log.SCAN_BLOCKED = True
	mail_log.FILTERS = None
	mail_log.VERBOSE = False
	
	spam_stats = {
		"received": 0,
		"blocked": 0,
	}
	
	try:
		with SilenceStdout():
			collector = mail_log.scan_mail_log(env)
		if collector:
			for user, data in collector.get("received_mail", {}).items():
				spam_stats["received"] += data.get("received_count", 0)
			for user, data in collector.get("rejected", {}).items():
				spam_stats["blocked"] += len(data.get("blocked", []))
	except Exception:
		pass
	finally:
		if orig_end: mail_log.END_DATE = orig_end
		if orig_now: mail_log.NOW = orig_now
		if orig_start: mail_log.START_DATE = orig_start
		
	return json_response({
		"dmarc": dmarc_stats,
		"spam_7days": spam_stats
	})

@app.route('/system/audit-log', methods=['GET'])
@authorized_personnel_only
def system_audit_log():
	try:
		page = int(request.args.get('page', 1))
		per_page = int(request.args.get('per_page', 50))
	except ValueError:
		return ("Invalid pagination parameters.", 400)
	page = max(1, page)
	per_page = min(max(1, per_page), 200)
	action = request.args.get('action', 'all')
	return json_response(audit.get_audit_log(page, per_page, action, env))

# APP


if __name__ == '__main__':
	if "DEBUG" in os.environ:
		# Turn on Flask debugging.
		app.debug = True

	if not app.debug:
		app.logger.addHandler(utils.create_syslog_handler())

	#app.logger.info('API key: ' + auth_service.key)

	# Start the application server. Listens on 127.0.0.1 (IPv4 only).
	app.run(port=10222)
