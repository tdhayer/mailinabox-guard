#!/bin/bash
#########################################################
# This script is intended to be run like this:
#
#   curl https://mailinabox.email/setup.sh | sudo bash
#
#########################################################

if [ -z "$TAG" ]; then
	# If a version to install isn't explicitly given as an environment
	# variable, then install the latest version. But the latest version
	# depends on the machine's version of Ubuntu. Existing users need to
	# be able to upgrade to the latest version available for that version
	# of Ubuntu to satisfy the migration requirements.
	#
	# Also, the system status checks read this script for TAG = (without the
	# space, but if we put it in a comment it would confuse the status checks!)
	# to get the latest version, so the first such line must be the one that we
	# want to display in status checks.
	#
	# Allow point-release versions of the major releases, e.g. 22.04.1 is OK.
	UBUNTU_VERSION=$( lsb_release -d | sed 's/.*:\s*//' | sed 's/\([0-9]*\.[0-9]*\)\.[0-9]/\1/' )
	if [ "$UBUNTU_VERSION" == "Ubuntu 22.04 LTS" ]; then
		# This machine is running Ubuntu 22.04, which is supported by
		# Mail-in-a-Box versions 60 and later.
		TAG=v76-guard
	elif [ "$UBUNTU_VERSION" == "Ubuntu 18.04 LTS" ]; then
		# This machine is running Ubuntu 18.04, which is supported by
		# Mail-in-a-Box versions 0.40 through 5x.
		echo "Support is ending for Ubuntu 18.04."
		echo "Please immediately begin to migrate your data to"
		echo "a new machine running Ubuntu 22.04. See:"
		echo "https://mailinabox.email/maintenance.html#upgrade"
		TAG=v57a
	elif [ "$UBUNTU_VERSION" == "Ubuntu 14.04 LTS" ]; then
		# This machine is running Ubuntu 14.04, which is supported by
		# Mail-in-a-Box versions 1 through v0.30.
		echo "Ubuntu 14.04 is no longer supported."
		echo "The last version of Mail-in-a-Box supporting Ubuntu 14.04 will be installed."
		TAG=v0.30
	else
		echo "This script may be used only on a machine running Ubuntu 14.04, 18.04, or 22.04."
		exit 1
	fi
fi

# Are we running as root?
if [[ $EUID -ne 0 ]]; then
	echo "This script must be run as root. Did you leave out sudo?"
	exit 1
fi

# Default source repository for Guard.
if [ "$SOURCE" == "" ]; then
	SOURCE=https://github.com/tdhayer/mailinabox-guard
fi

# If a directory exists but it isn't a git checkout, stop and ask the user
# to move it out of the way rather than guessing how to proceed.
if [ -d "$HOME/mailinabox" ] && [ ! -d "$HOME/mailinabox/.git" ]; then
	echo "Found $HOME/mailinabox but it is not a git repository."
	echo "Please move it aside and run this script again."
	exit 1
fi

# Clone the Mail-in-a-Box repository if it doesn't exist.
if [ ! -d "$HOME/mailinabox" ]; then
	if [ ! -f /usr/bin/git ]; then
		echo "Installing git . . ."
		apt-get -q -q update
		DEBIAN_FRONTEND=noninteractive apt-get -q -q install -y git < /dev/null
		echo
	fi

	echo "Downloading Mail-in-a-Box $TAG. . ."
	git clone \
		-b "$TAG" --depth 1 \
		"$SOURCE" \
		"$HOME/mailinabox" \
		< /dev/null 2> /dev/null

	echo
fi

# Change directory to it.
cd "$HOME/mailinabox" || exit

# Migration preflight for existing installs: if the requested tag doesn't
# exist on the current origin, switch origin to SOURCE and preserve the
# previous origin as upstream.
CURRENT_ORIGIN=$(git remote get-url origin 2>/dev/null || /bin/true)
if [ -n "$CURRENT_ORIGIN" ] && [ "$CURRENT_ORIGIN" != "$SOURCE" ]; then
	if ! git ls-remote --exit-code --tags origin "refs/tags/$TAG" > /dev/null 2>&1; then
		echo ""
		echo "Existing repository origin ($CURRENT_ORIGIN) does not provide tag $TAG."
		echo "Switching origin to $SOURCE for migration to Mail-in-a-Box Guard."

		if git remote | grep -q "^upstream$"; then
			git remote set-url upstream "$CURRENT_ORIGIN"
		else
			git remote add upstream "$CURRENT_ORIGIN"
		fi

		git remote set-url origin "$SOURCE"
	fi
fi

# Update it. Always re-fetch the tag so that force-pushed tags (moved to a
# new commit) are picked up — comparing tag names alone would miss this.
echo "Updating Mail-in-a-Box to $TAG . . ."
git fetch --depth 1 --force --prune origin tag "$TAG"
if ! git checkout -q "$TAG"; then
	echo "Update failed. Did you modify something in $PWD?"
	exit 1
fi
echo

# Start setup script.
setup/start.sh
