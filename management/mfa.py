import base64
import hmac
import io
import os
import pyotp
import qrcode
import json

from mailconfig import open_database

try:
	from webauthn import generate_registration_options, verify_registration_response, generate_authentication_options, verify_authentication_response, options_to_json
	from webauthn.helpers.structs import PublicKeyCredentialDescriptor, AuthenticatorSelectionCriteria, AuthenticatorAttachment
	from webauthn.helpers import bytes_to_base64url, base64url_to_bytes
	WEBAUTHN_AVAILABLE = True
except ImportError:
	WEBAUTHN_AVAILABLE = False

def get_user_id(email, c):
	c.execute('SELECT id FROM users WHERE email=?', (email,))
	r = c.fetchone()
	if not r: raise ValueError("User does not exist.")
	return r[0]

def get_mfa_state(email, env):
	c = open_database(env)
	c.execute('SELECT id, type, secret, mru_token, label FROM mfa WHERE user_id=?', (get_user_id(email, c),))
	return [
		{ "id": r[0], "type": r[1], "secret": r[2], "mru_token": r[3], "label": r[4] }
		for r in c.fetchall()
	]

def get_public_mfa_state(email, env):
	mfa_state = get_mfa_state(email, env)
	return [
		{ "id": s["id"], "type": s["type"], "label": s["label"] }
		for s in mfa_state
	]

def get_hash_mfa_state(email, env):
	mfa_state = get_mfa_state(email, env)
	return [
		{ "id": s["id"], "type": s["type"], "secret": s["secret"] }
		for s in mfa_state
	]

def enable_mfa(email, type, secret, token, label, env):
	if type == "totp":
		validate_totp_secret(secret)
		# Sanity check with the provide current token.
		totp = pyotp.TOTP(secret)
		if not totp.verify(token, valid_window=1):
			msg = "Invalid token."
			raise ValueError(msg)
	elif type == "webauthn":
		# The secret is already validated and formatted in register_webauthn
		pass
	else:
		msg = "Invalid MFA type."
		raise ValueError(msg)

	conn, c = open_database(env, with_connection=True)
	c.execute('INSERT INTO mfa (user_id, type, secret, label) VALUES (?, ?, ?, ?)', (get_user_id(email, c), type, secret, label))
	conn.commit()

def set_mru_token(email, mfa_id, token, env):
	conn, c = open_database(env, with_connection=True)
	c.execute('UPDATE mfa SET mru_token=? WHERE user_id=? AND id=?', (token, get_user_id(email, c), mfa_id))
	conn.commit()

def disable_mfa(email, mfa_id, env):
	conn, c = open_database(env, with_connection=True)
	if mfa_id is None:
		# Disable all MFA for a user.
		c.execute('DELETE FROM mfa WHERE user_id=?', (get_user_id(email, c),))
	else:
		# Disable a particular MFA mode for a user.
		c.execute('DELETE FROM mfa WHERE user_id=? AND id=?', (get_user_id(email, c), mfa_id))
	conn.commit()
	return c.rowcount > 0

def validate_totp_secret(secret):
	if not isinstance(secret, str) or secret.strip() == "":
		msg = "No secret provided."
		raise ValueError(msg)
	if len(secret) != 32:
		msg = "Secret should be a 32 characters base32 string"
		raise ValueError(msg)

def provision_totp(email, env):
	# Make a new secret.
	secret = base64.b32encode(os.urandom(20)).decode('utf-8')
	validate_totp_secret(secret) # sanity check

	# Make a URI that we encode within a QR code.
	uri = pyotp.TOTP(secret).provisioning_uri(
		name=email,
		issuer_name=env["PRIMARY_HOSTNAME"] + " Mail-in-a-Box Control Panel"
	)

	# Generate a QR code as a base64-encode PNG image.
	qr = qrcode.make(uri)
	byte_arr = io.BytesIO()
	qr.save(byte_arr, format='PNG')
	png_b64 = base64.b64encode(byte_arr.getvalue()).decode('utf-8')

	return {
		"type": "totp",
		"secret": secret,
		"qr_code_base64": png_b64
	}

def provision_webauthn(email, env, auth_service):
	if not WEBAUTHN_AVAILABLE:
		raise ValueError("WebAuthn is not available. Please install the webauthn package.")
		
	rp_id = env["PRIMARY_HOSTNAME"]
	rp_name = f"{rp_id} Mail-in-a-Box Control Panel"
	
	options = generate_registration_options(
		rp_id=rp_id,
		rp_name=rp_name,
		user_id=email.encode('utf-8'),
		user_name=email,
		user_display_name=email,
		authenticator_selection=AuthenticatorSelectionCriteria(
			authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM
		)
	)
	
	options_json = json.loads(options_to_json(options))
	auth_service.webauthn_challenges[email] = options_json["challenge"]
	
	return options_json

def register_webauthn(email, response_data, label, env, auth_service):
	if not WEBAUTHN_AVAILABLE:
		raise ValueError("WebAuthn is not available.")
		
	challenge = auth_service.webauthn_challenges.get(email)
	if not challenge:
		raise ValueError("WebAuthn challenge expired or missing.")
		
	rp_id = env["PRIMARY_HOSTNAME"]
	expected_origin = f"https://{rp_id}"
	
	try:
		verification = verify_registration_response(
			credential=response_data,
			expected_challenge=base64url_to_bytes(challenge),
			expected_origin=expected_origin,
			expected_rp_id=rp_id,
			require_user_verification=True
		)
	except Exception as e:
		raise ValueError(f"WebAuthn registration failed: {str(e)}")
		
	secret_data = {
		"credential_id": bytes_to_base64url(verification.credential_id),
		"public_key": bytes_to_base64url(verification.credential_public_key),
		"sign_count": verification.sign_count
	}
	
	del auth_service.webauthn_challenges[email]
	
	enable_mfa(email, "webauthn", json.dumps(secret_data), "", label, env)

def validate_auth_mfa(email, request, env, auth_service=None):
	# Validates that a login request satisfies any MFA modes
	# that have been enabled for the user's account. Returns
	# a tuple (status, [hints]). status is True for a successful
	# MFA login, False for a missing token. If status is False,
	# hints is an array of codes that indicate what the user
	# can try. Possible codes are:
	# "missing-totp-token"
	# "invalid-totp-token"

	mfa_state = get_mfa_state(email, env)

	# If no MFA modes are added, return True.
	if len(mfa_state) == 0:
		return (True, [])

	webauthn_devices = [m for m in mfa_state if m["type"] == "webauthn"]

	# Try the enabled MFA modes.
	hints = set()
	for mfa_mode in mfa_state:
		if mfa_mode["type"] == "totp":
			# Check that a token is present in the X-Auth-Token header.
			# If not, give a hint that one can be supplied.
			token = request.headers.get('x-auth-token')
			if not token:
				hints.add("missing-totp-token")
				continue

			# Check for a replay attack.
			if hmac.compare_digest(token, mfa_mode['mru_token'] or ""):
				# If the token fails, skip this MFA mode.
				hints.add("invalid-totp-token")
				continue

			# Check the token.
			totp = pyotp.TOTP(mfa_mode["secret"])
			if not totp.verify(token, valid_window=1):
				hints.add("invalid-totp-token")
				continue

			# On success, record the token to prevent a replay attack.
			set_mru_token(email, mfa_mode['id'], token, env)
			return (True, [])
			
		elif mfa_mode["type"] == "webauthn" and WEBAUTHN_AVAILABLE:
			token = request.headers.get('x-auth-token')
			if not token or not token.startswith("webauthn:"):
				# Will handle challenge generation below after checking all modes
				pass
			else:
				# Verify token
				try:
					response_data = json.loads(token.split("webauthn:", 1)[1])
					# To verify, we need the auth_service challenge
					challenge = auth_service.webauthn_challenges.get(email)
					if not challenge:
						hints.add("invalid-webauthn-token")
						continue
						
					cred_id = response_data.get("id")
					device = next((m for m in webauthn_devices if json.loads(m["secret"])["credential_id"] == cred_id), None)
					if not device:
						hints.add("invalid-webauthn-token")
						continue
						
					secret_data = json.loads(device["secret"])
					
					verification = verify_authentication_response(
						credential=response_data,
						expected_challenge=base64url_to_bytes(challenge),
						expected_origin=f"https://{env['PRIMARY_HOSTNAME']}",
						expected_rp_id=env["PRIMARY_HOSTNAME"],
						credential_public_key=base64url_to_bytes(secret_data["public_key"]),
						credential_current_sign_count=secret_data["sign_count"],
						require_user_verification=True
					)
					
					# Update sign count
					secret_data["sign_count"] = verification.new_sign_count
					conn, c = open_database(env, with_connection=True)
					c.execute('UPDATE mfa SET secret=? WHERE id=?', (json.dumps(secret_data), device["id"]))
					conn.commit()
					
					del auth_service.webauthn_challenges[email]
					return (True, [])
				except Exception:
					hints.add("invalid-webauthn-token")
					continue

	# If we have webauthn modes and need a challenge
	if webauthn_devices and WEBAUTHN_AVAILABLE:
		token = request.headers.get('x-auth-token')
		if not token or not token.startswith("webauthn:"):
			allow_credentials = [
				PublicKeyCredentialDescriptor(id=base64url_to_bytes(json.loads(m["secret"])["credential_id"]))
				for m in webauthn_devices
			]
			options = generate_authentication_options(
				rp_id=env["PRIMARY_HOSTNAME"],
				allow_credentials=allow_credentials
			)
			options_json = json.loads(options_to_json(options))
			if auth_service:
				auth_service.webauthn_challenges[email] = options_json["challenge"]
			hints.add("missing-webauthn-token:" + json.dumps(options_json))

	# On a failed login, indicate failure and any hints for what the user can do instead.
	return (False, list(hints))