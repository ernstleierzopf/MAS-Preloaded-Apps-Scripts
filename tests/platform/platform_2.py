"""PLATFORM-2 - MASTG-TEST-0025, MASTG-TEST-0027"""
import os.path
import subprocess
import datetime
import logging


def check(wdir, apk, apk_hash, package_name, report, fail_counts, findings):
    """
    The primary objective is to search for potential SQL injection in queries.
    A main regex to search for these queries is applied.
    E.g:
    "SELECT Column FROM Table WHERE id = " + input_variable + " ... ;"
    May suggest that a user could inject malicious SQL code to cause an injection.
    If a match with these queries is registered, it may conclude in an INCONCLUSIVE.
    Dynamic analysis: Add drozer module to query and extract potential injections in content providers.
    Drozer can be launched in cmdline.
    docker run fsecurelabs/drozer /bin/bash -c "drozer console connect --server 192.168.3.14 -c 'run scanner.provider.injection -a com.android.chrome'";
    """
    verdict = 'FAIL'
    total_matches = 0
    regex_1 = "\"\\\"[ ]*(ALTER|CREATE|DELETE|DROP|EXEC(UTE){0,1}|INSERT( +INTO){0,1}|MERGE|SELECT|UPDATE|UNION( +ALL){0,1})[ ]+[a-zA-Z0-9\\ \\*_\\-\\=]+(\\ |\\\")[ ]?\\+[ ]*[a-zA-Z0-9\\ \\*_\\-]+\""
    regex_2 = "\"shouldOverrideUrlLoading\\(.*\\)[ ]*{[\\n\\s\\t]*(return false;)\""
    #cmd_webview = f'grep -rnwz -E {wdir}/decompiled | wc -l'
    sources = os.path.join(wdir, "decompiled", "sources")
    cmd = f"grep -rnws --exclude='*.dex' -E {regex_1} {sources}"
    ct = datetime.datetime.now()
    try:
        output = subprocess.check_output(cmd, shell=True).splitlines()
        if len(output) > 0:
            total_matches += len(output)
            for match in output:
                match_str = match.decode()
                try:
                    if '.java' in match_str:
                        match_file = match_str.split(":")[0]
                        match_line = match_str.split(":")[1]
                        findings.append("%s;%s;Platform;Platform-2;%s;%s" % (apk_hash, package_name, match_file, match_line))
                    else:
                        findings.append("%s;%s;Platform;Platform-2;%s;-" % (apk_hash, package_name, match_str))
                except:
                    msg = "%s;%s;%s;Platform-2;It was not possible to get match_file or match_line" % (apk_hash, package_name, ct)
                    logging.error(msg)
                    verdict = "NA"
    except subprocess.CalledProcessError as e:
        if e.returncode != 1:
            msg = "%s;%s;%s;Platform-2;grep command failed due to %s does not exists" % (apk_hash, package_name, ct, sources)
            logging.error(msg)
            verdict = "NA"
    except:
        msg = "%s;%s;%s;Platform-2;grep failed for %s" % (apk_hash, package_name, ct, regex_1)
        logging.error(msg)
        verdict = "NA"

    cmd = f"grep -rlnwzs --exclude='*.dex' -P {regex_2} {sources}"
    try:
        output = subprocess.check_output(cmd, shell=True).splitlines()
        if len(output) > 0:
            total_matches += len(output)
            for match in output:
                match_str = match.decode()
                try:
                    findings.append("%s;%s;Platform;Platform-2;%s;-" % (apk_hash, package_name, match_str))
                except:
                    msg = "%s;%s;%s;Platform-2;It was not possible to get match_str" % (apk_hash, package_name, ct)
                    logging.error(msg)
                    verdict = "NA"
    except subprocess.CalledProcessError as e:
        if e.returncode != 1:
            msg = "%s;%s;%s;Platform-2;grep command failed due to %s does not exists" % (apk_hash, package_name, ct, sources)
            logging.error(msg)
            verdict = "NA"
    except:
        msg = "%s;%s;%s;Platform-2;grep failed for %s" % (apk_hash, package_name, ct, regex_2)
        logging.error(msg)
        verdict = "NA"
    if total_matches == 0:
        verdict = 'PASS'
    report["Platform-2"] = verdict
    fail_counts["Platform-2"] = total_matches
    print('Platform-2 successfully tested.')
    return [verdict, total_matches]
