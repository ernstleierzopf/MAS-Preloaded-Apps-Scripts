"""NETWORK-1 - MASTG-TEST-0066"""
import os.path
import subprocess
import datetime
from utils.auxiliar_functions import get_suid_from_manifest
import utils.check_network1_redirects as network1


def check(wdir, apk, apk_hash, package_name, report, fail_counts, findings):
    """
        Check if there is any URL with "http" schema.
        URLs are extracted from the static decompiled code.
        In the case there is at least one, it is INCONCLUSIVE (Manual review is required, as many of these URLs are static resources and not
        relevant to security purposes), otherwise, PASS.
        An auxiliar file with those found URLs is provided for manual review.
    """
    verdict = 'FAIL'
    total_matches = 0
    http_location = os.path.join(wdir, "/http_net2.txt")
    with open(http_location) as f:
        lines = len(f.readlines())
    ct = datetime.datetime.now()
    if lines > 0:
        try:
            total_matches = network1.check(http_location, apk_hash, package_name, uuid_execution)
            if total_matches == 0:
                verdict = 'PASS'
        except subprocess.CalledProcessError as e:
            if e.returncode != 1:
                msg = "%s;%s;%s;NETWORK-1;Check redirects script failed" % (apk_hash, package_name, ct)
                logging.error(msg)
                verdict = "NA"
        except:
            msg = "%s;%s;%s;NETWORK-1;Check redirects script failed" % (apk_hash, package_name, ct)
            logging.error(msg)
            verdict = "NA"
    else:
        verdict = 'PASS'
    report["NETWORK-1"] = verdict
    fail_counts["NETWORK-1"] = total_matches
    print('NETWORK-1 successfully tested.')
    return [verdict, total_matches]
