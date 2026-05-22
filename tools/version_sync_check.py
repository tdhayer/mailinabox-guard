#!/usr/bin/env python3
import os
import re
import sys
import argparse
from pathlib import Path


def get_paths():
	base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
	return {"changelog": os.path.join(base_dir, "CHANGELOG.md"), "version": os.path.join(base_dir, "VERSION"), "bootstrap": os.path.join(base_dir, "setup", "bootstrap.sh")}


def extract_latest_changelog(changelog_path):
	if not os.path.exists(changelog_path):
		print(f"Error: Changelog file not found at {changelog_path}", file=sys.stderr)
		sys.exit(1)

	with open(changelog_path, encoding="utf-8") as f:
		lines = f.readlines()

	version = None
	section_lines = []
	recording = False

	for line in lines:
		match = re.match(r"^Version\s+([\w.-]+)\s+\(.*\)", line)
		if match:
			if not version:
				version = match.group(1)
				recording = True
				continue
			# Reached the next version header
			break
		if recording:
			section_lines.append(line)

	if not version:
		print("Error: Could not find any Version header in CHANGELOG.md", file=sys.stderr)
		sys.exit(1)

	# Remove leading underline if it exists
	if section_lines:
		first_line = section_lines[0].strip()
		if first_line.startswith(("---", "===")):
			section_lines.pop(0)

	changelog_content = "".join(section_lines).strip()
	return version, changelog_content


def check_version_file(version_path, expected_version):
	if not os.path.exists(version_path):
		print(f"Error: VERSION file not found at {version_path}", file=sys.stderr)
		return False

	version_content = Path(version_path).read_text(encoding="utf-8").strip()

	if version_content != expected_version:
		print(f"Mismatch: VERSION file has '{version_content}', but CHANGELOG.md has '{expected_version}'", file=sys.stderr)
		return False

	print(f"Success: VERSION file matches CHANGELOG.md version '{expected_version}'")
	return True


def check_bootstrap_file(bootstrap_path, expected_version):
	if not os.path.exists(bootstrap_path):
		print(f"Error: bootstrap.sh not found at {bootstrap_path}", file=sys.stderr)
		return False

	expected_tag = f"v{expected_version}"
	tag_pattern = re.compile(r"^\s*TAG=([\w.-]+)")
	found_tag = None

	with open(bootstrap_path, encoding="utf-8") as f:
		for line in f:
			match = tag_pattern.match(line)
			if match:
				found_tag = match.group(1)
				break

	if not found_tag:
		print(f"Error: Could not find TAG= assignment in {bootstrap_path}", file=sys.stderr)
		return False

	if found_tag != expected_tag:
		print(f"Mismatch: bootstrap.sh has TAG='{found_tag}', but expected '{expected_tag}'", file=sys.stderr)
		return False

	print(f"Success: bootstrap.sh TAG matches expected tag '{expected_tag}'")
	return True


def main():
	parser = argparse.ArgumentParser(description="Check version synchronization across CHANGELOG.md, VERSION, and bootstrap.sh")
	parser.add_argument("--tag", help="Check if the provided git tag matches the project version")
	parser.add_argument("--extract-changelog", action="store_true", help="Print the latest changelog notes and exit")
	args = parser.parse_args()

	paths = get_paths()

	version, changelog_content = extract_latest_changelog(paths["changelog"])

	if args.extract_changelog:
		print(changelog_content)
		sys.exit(0)

	success = True

	# Check VERSION file
	if not check_version_file(paths["version"], version):
		success = False

	# Check bootstrap.sh
	if not check_bootstrap_file(paths["bootstrap"], version):
		success = False

	# Check git tag if provided
	if args.tag:
		expected_tag = f"v{version}"
		if args.tag != expected_tag:
			print(f"Mismatch: Git tag is '{args.tag}', but codebase expected tag is '{expected_tag}'", file=sys.stderr)
			success = False
		else:
			print(f"Success: Pushed git tag '{args.tag}' matches codebase expected tag")

	if not success:
		sys.exit(1)

	print("All version sync checks passed successfully.")


if __name__ == "__main__":
	main()
