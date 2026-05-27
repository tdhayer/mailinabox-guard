#!/usr/local/lib/mailinabox/env/bin/python3

import os
import glob
import gzip
import zipfile
import time
import xml.etree.ElementTree as ET
from utils import load_environment

def run_dmarc_check():
	env = load_environment()
	dmarc_dir = os.path.join(env["STORAGE_ROOT"], "mail", "dmarc")

	if not os.path.exists(dmarc_dir):
		return

	# Look for files modified in the last 24 hours (86400 seconds)
	now = time.time()
	one_day_ago = now - 86400

	files = []
	for ext in ["*.xml", "*.xml.gz", "*.zip", "*.gz"]:
		files.extend(glob.glob(os.path.join(dmarc_dir, ext)))

	# Filter by modification time and deduplicate
	files = list(set(f for f in files if os.path.getmtime(f) >= one_day_ago))

	if not files:
		return

	total_messages = 0
	spf_fail = 0
	dkim_fail = 0

	for fpath in files:
		try:
			content = None
			if fpath.endswith(".gz") or fpath.endswith(".xml.gz"):
				with gzip.open(fpath, "rb") as f:
					content = f.read()
			elif fpath.endswith(".zip"):
				with zipfile.ZipFile(fpath, "r") as z:
					for name in z.namelist():
						if name.endswith(".xml"):
							content = z.read(name)
							break
			else:
				with open(fpath, "rb") as f:
					content = f.read()

			if not content:
				continue

			root = ET.fromstring(content) # nosec B314
			for record in root.findall(".//record"):
				count_el = record.find(".//row/count")
				count = int(count_el.text) if count_el is not None else 1

				total_messages += count

				policy = record.find(".//row/policy_evaluated")
				if policy is not None:
					dkim_el = policy.find("dkim")
					if dkim_el is not None and dkim_el.text != "pass":
						dkim_fail += count
					elif dkim_el is None:
						dkim_fail += count

					spf_el = policy.find("spf")
					if spf_el is not None and spf_el.text != "pass":
						spf_fail += count
					elif spf_el is None:
						spf_fail += count
				else:
					dkim_fail += count
					spf_fail += count

		except Exception:
			pass

	if total_messages >= 5:
		spf_fail_rate = (spf_fail / total_messages) * 100
		dkim_fail_rate = (dkim_fail / total_messages) * 100

		if spf_fail_rate > 10.0 or dkim_fail_rate > 10.0:
			print("WARNING: High DMARC Authentication Failure Rates Detected!")
			print("")
			print("In the last 24 hours, aggregate DMARC reports show a high rate of SPF or DKIM validation failures for emails sent from your domain(s).")
			print("")
			print(f"Total Messages Reported: {total_messages}")
			print(f"SPF Failures: {spf_fail} ({spf_fail_rate:.1f}%)")
			print(f"DKIM Failures: {dkim_fail} ({dkim_fail_rate:.1f}%)")
			print("")
			print("Please verify your SPF and DKIM DNS records and mail server configuration.")

if __name__ == "__main__":
	run_dmarc_check()
