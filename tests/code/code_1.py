"""CODE-1 - MASTG-TEST-0081"""

from utils.auxiliar_functions import check_signature


def check(wdir, apk, apk_hash, package_name, report, fail_counts, findings):
    verdict = 'FAIL'
    total_matches = 0
    output_sign_count = 0
    signature_info = check_signature(wdir, apk, apk_hash, package_name)
    if signature_info:
        for i in signature_info:
            if "v2): true" in i or "v3): true" in i:
                output_sign_count += 1
    if output_sign_count >= 1:
        verdict = 'PASS'
    else:
        total_matches = 1
    report["CODE-1"] = verdict
    fail_counts["CODE-1"] = total_matches
    print('CODE-1 successfully tested.')
    return [verdict, total_matches]
