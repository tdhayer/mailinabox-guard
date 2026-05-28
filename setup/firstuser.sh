#!/bin/bash
# If there aren't any mail users yet, create one.
if [ -z "$(management/cli.py user)" ]; then
	# The output of "management/cli.py user" is a list of mail users. If there
	# aren't any yet, it'll be empty.

	# If we didn't ask for an email address at the start, do so now.
	if [ -z "${EMAIL_ADDR:-}" ]; then
		# In an interactive shell, ask the user for an email address.
		if [ -z "${NONINTERACTIVE:-}" ]; then
			input_box "Mail Account" \
				"Let's create your first mail account.
				\n\nWhat email address do you want?" \
				"me@$(get_default_hostname)" \
				EMAIL_ADDR

			if [ -z "$EMAIL_ADDR" ]; then
				# user hit ESC/cancel
				exit
			fi
			while ! management/mailconfig.py validate-email "$EMAIL_ADDR"
			do
				input_box "Mail Account" \
					"That's not a valid email address.
					\n\nWhat email address do you want?" \
					"$EMAIL_ADDR" \
					EMAIL_ADDR
				if [ -z "$EMAIL_ADDR" ]; then
					# user hit ESC/cancel
					exit
				fi
			done

		# But in a non-interactive shell, just make something up.
		# This is normally for testing.
		else
			# Use me@PRIMARY_HOSTNAME
			EMAIL_ADDR=me@$PRIMARY_HOSTNAME
			EMAIL_PW=Admin1234!Test
			echo
			echo "Creating a new administrative mail account for $EMAIL_ADDR with password $EMAIL_PW."
			echo
		fi
	else
		echo
		echo "Okay. I'm about to set up $EMAIL_ADDR for you. This account will also"
		echo "have access to the box's control panel."
	fi

	# Create the user's mail account. This will ask for a password if none was given above.
	# Loop so the user can retry if something goes wrong (e.g. mismatched confirmation).
	while true; do
		if management/cli.py user add "$EMAIL_ADDR" ${EMAIL_PW:+"$EMAIL_PW"}; then
			break
		fi
		# Only retry in interactive mode; in non-interactive (testing) mode, bail out.
		if [ -n "${NONINTERACTIVE:-}" ]; then
			echo "Failed to create mail account." >&2
			exit 1
		fi
		echo
		echo "Failed to create the mail account. Please try again."
		echo
	done

	# Make it an admin.
	hide_output management/cli.py user make-admin "$EMAIL_ADDR"

	# Create an alias to which we'll direct all automatically-created administrative aliases.
	management/cli.py alias add "administrator@$PRIMARY_HOSTNAME" "$EMAIL_ADDR" > /dev/null
fi
