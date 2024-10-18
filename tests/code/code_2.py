"""CODE-2 - MASTG-TEST-0082"""

import os
from utils.auxiliar_functions import check_debuggable


def check(wdir, apk, apk_hash, package_name, report, fail_counts, findings):
    verdict = 'FAIL'
    total_matches = 0
    debug_info = check_debuggable(os.path.join(wdir, apk.replace(".apk", "")), apk_hash, package_name)
    if debug_info == 'No relevant results':
        verdict = 'PASS'
    else:
        total_matches = 1
        match_line = debug_info[0].decode().strip().split(':', 1)[0]
        findings.append("%s;%s;CODE;CODE-2;%s;%s" % (apk_hash, package_name, os.path.join(wdir, apk.replace(".apk", ""), "AndroidManifest.xml"), match_line))
    report["CODE-2"] = verdict
    fail_counts["CODE-2"] = total_matches
    print('CODE-2 successfully tested.')
    return [verdict, total_matches]
