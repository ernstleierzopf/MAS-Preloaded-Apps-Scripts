"""CRYPTO-3 - MASTG-TEST-0014"""
import os.path
import subprocess
import datetime
import logging

def check(wdir, apk, apk_hash, package_name, report, fail_counts, findings):
    """
        Check for potentially vulnerable algorithms in the code.
        If a match is found, FAIL is set, otherwise PASS
    """
    verdict = 'FAIL'
    total_matches = 0
    vuln_algo = ["\"AES/CBC/PKCS5Padding\"", "\"DES/CBC/PKCS5Padding\"", "\".*\\/ECB\"", "\"^(TLS).*-CBC-.*\""]
    ct = datetime.datetime.now()
    sources_path = os.path.join(wdir, "decompiled", "sources")
    for i in vuln_algo:
        cmd = f"grep -rnws --exclude='*.dex' -E {i} {sources_path}"
        try:
            output = subprocess.check_output(cmd, shell=True).splitlines()
            if len(output) > 0:
                for match in output:
                    match_str = match.decode()
                    try:
                        if '.java' in match_str:
                            match_file = match_str.split(":")[0]
                            match_line = match_str.split(":")[1] 
                            total_matches += 1
                            findings.append("%s;%s;CRYPTO;CRYPTO-3;%s;%s" % (apk_hash, package_name, match_file, match_line))
                        else:
                            total_matches += 1
                            findings.append("%s;%s;CRYPTO;CRYPTO-3;%s;-" % (apk_hash, package_name, match_str))
                    except:
                        msg = "%s;%s;%s;CRYPTO-3;It was not possible to get match_file or match_line" % (apk_hash, package_name, ct)
                        logging.error(msg)
        except subprocess.CalledProcessError as e:
            if e.returncode != 1:
                msg = "%s;%s;%s;CRYPTO-3;grep command failed due to %s does not exists" % (apk_hash, package_name, ct, sources_path)
                logging.error(msg)
        except:
            msg = "%s;%s;%s;CRYPTO-3;grep command failed for %s" % (apk_hash, package_name, ct, i)
            logging.error(msg)
    if total_matches == 0:
        verdict = 'PASS'
    report["CRYPTO-3"] = verdict
    fail_counts["CRYPTO-3"] = total_matches
    print('CRYPTO-3 successfully tested.')
    return [verdict, total_matches]
