"""CRYPTO-1 - MASTG-TEST-0013"""

import subprocess
import datetime
import logging
import os


def check(wdir, apk, apk_hash, package_name, report, fail_counts, findings):
    """
        Hardcoded Byte arrays, b64 str or final Strings in files where crypto lib are imported
        Key generation with hardcoded parameters
        Triple backward slash to get escaped \"
        Output is always multiline, so len of output is not necessarily required, only a match is enough.
        However, if other regular expressions are imported, it may be useful in the future 
    """
    verdict = 'FAIL'
    total_matches = 0
    regex_1 = "\"import java(x)?\.(security|crypto).*;(\\n|.)*((final String [a-zA-Z0-9]+[ ]*\\=)|(==\\\")|(byte\\[\\] [a-zA-Z0-9]* = [{]{1}[ ]?[0-9]+)|(SecretKeySpec\\(((\\{[0-9]+)|(\\\"[a-zA-Z0-9]+\\\"))))\""
    regex_2 = "\"Lcom\/jiolib\/libclasses\/utils\/AesUtil\""
    ct = datetime.datetime.now()

    sources_path = os.path.join(wdir, "decompiled", "sources")
    cmd = f"grep -rlnwzs --exclude='*.dex' -E {regex_1} {sources_path}"
    try:
        output = subprocess.check_output(cmd, shell=True).splitlines()
        if len(output) > 0:
            total_matches += len(output)
            for match in output:
                match_file = match.decode()
                findings.append("%s;%s;CRYPTO;CRYPTO-1;%s;-" % (apk_hash, package_name, match_file))
    except subprocess.CalledProcessError as e:
        if e.returncode != 1:
            msg = "%s;%s;%s;CRYPTO-1;grep command failed due to %s does not exists" % (apk_hash, package_name, ct, sources_path)
            logging.error(msg)
    except:
        msg = "%s;%s;%s;CRYPTO-1;grep command failed for %s" % (apk_hash, package_name, ct, regex_1)
        logging.error(msg)

    cmd = f"grep -rlnws --exclude='*.dex' -E {regex_2} {sources_path}"
    try:
        output = subprocess.check_output(cmd, shell=True).splitlines()
        if len(output) > 0:
            total_matches += len(output)
            for match in output:
                match_file = match.decode().split(":")[0]
                match_line = match.decode().split(":")[1]
                findings.append("%s;%s;CRYPTO;CRYPTO-1;%s;%s" % (apk_hash, package_name, match_file, match_line))
    except subprocess.CalledProcessError as e:
        if e.returncode != 1:
            msg = "%s;%s;%s;CRYPTO-1;grep command failed due to %s does not exists" % (apk_hash, package_name, ct, sources_path)
            logging.error(msg)
    except:
        msg = "%s;%s;%s;CRYPTO-1;grep command failed for %s" % (apk_hash, package_name, ct, regex_2)
        logging.error(msg)

    if total_matches == 0:
        verdict = 'PASS'
    report["CRYPTO-1"] = verdict
    fail_counts["CRYPTO-1"] = total_matches
    print('CRYPTO-1 successfully tested.')
    return [verdict, total_matches]
