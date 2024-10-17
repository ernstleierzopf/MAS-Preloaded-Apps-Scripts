"""NETWORK-2 - MASTG-TEST-0020"""
import os.path
import subprocess
import datetime
from settings import PATH_TESTSSL
from utils.auxiliar_functions import get_suid_from_manifest, remove_last_backslash


def check(wdir, apk, apk_hash, package_name, report, fail_counts, findings):
    """
        Check for potentially vulnerable TLS configurations.
        If a match is found, INCONCLUSIVE is set, could be a potential FAIL
        This case creates a report that shall be reviewed manually to inspect for a verdict in the Test Case

        Future work: check with a whitelist of URLs if they are considered PASS even if they allow TLS1 or TLS1.1 according to ciphersuites.
    """
    verdict = 'PASS'
    total_matches = 0
    grep_filter = "\"((TLSv1:)|(TLSv1.1:)).*(-DES-[A-Z0-9]+)\""
    ct = datetime.datetime.now()
    filtered_path = os.path.join(wdir, "_filtered_net2.txt")
    with open(filtered_path) as all_urls:
        for url in all_urls:
            url_total_match = 0
            url_no_breakline = url.rstrip("\n")
            final_url = remove_last_backslash(url_no_breakline)
            cmd = f'echo no | {PATH_TESTSSL} -P {final_url} 2>/dev/null | grep -E {grep_filter} | wc -l'
            try:
                output = subprocess.check_output(cmd, shell=True).splitlines()
                if int(output[0]) > 0:
                    total_matches += 1
                    url_total_match = 1
            except subprocess.CalledProcessError as e:
                if e.returncode != 1:
                    msg = "%s;%s;%s;NETWORK-2;Command failed." % (apk_hash, package_name, ct)
                    logging.error(msg)
                    verdict = "NA"
            except:
                msg = "%s;%s;%s;NETWORK-2;Command failed." % (apk_hash, package_name, ct)
                logging.error(msg)
                verdict = "NA"
            if url_total_match > 0:
                verdict = 'Needs Review'
            findings.append("%s;%s;NETWORK;NETWORK-2;%s;%s" % (apk_hash, package_name, url_no_breakline, verdict))
    report["NETWORK-2"] = verdict
    fail_counts["NETWORK-2"] = total_matches
    print('NETWORK-2 successfully tested.')
    return [verdict, total_matches]
