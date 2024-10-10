"""NETWORK-3 - MASTG-TEST-0021"""
import os.path
import subprocess
import datetime
import db.database_utils as database_utils
from utils.auxiliar_functions import get_suid_from_manifest


def check(wdir, apk, apk_hash, package_name, report, fail_counts, findings):
    verdict = 'FAIL'
    net_config = False
    low_target_sdk = False
    total_matches = 0
    verifier_check = "\"(import java(x)?\\.(.*)HostnameVerifier;)\""
    cmd = "cat %s |  egrep -iE 'android:networkSecurityConfig' | wc -l" % os.path.join(wdir, apk.replace(".apk", ""), "AndroidManifest.xml")
    ct = datetime.datetime.now()
    try:
        output = subprocess.check_output(cmd, shell=True).strip()
        if int(output) > 0:
            net_config = True
    except subprocess.CalledProcessError as e:
        if e.returncode != 1:
            net_config = False
            msg = "%s;%s;%s;NETWORK-3;Network security config file grep error" % (apk_hash, package_name, ct)
            logging.error(msg)
    except:
        net_config = False
        msg = "%s;%s;%s;NETWORK-3;Network security config file grep error" % (apk_hash, package_name, ct)
        logging.error(msg)

    cmd_get_target_sdk = f'cat %s | grep -Po \"(?<=android:targetSdkVersion=)\\"[^\\"]+\\"\" | sed \'s/\"//g\'' % os.path.join(wdir, apk.replace(".apk", ""), "AndroidManifest.xml")
    try:
        output = subprocess.check_output(cmd_get_target_sdk, shell=True).splitlines()
        if int(int(output[0])) < 24:
            low_target_sdk = True
    except subprocess.CalledProcessError as e:
        if e.returncode != 1:
            low_target_sdk = False
            msg = "%s;%s;%s;NETWORK-3;Target sdk grep error" % (apk_hash, package_name, ct)
            logging.error(msg)
    except:
        low_target_sdk = False
        msg = "%s;%s;%s;NETWORK-3;Target sdk grep error" % (apk_hash, package_name, ct)
        logging.error(msg)

    sources = os.path.join(wdir, "decompiled", "sources")
    cmd_check_hostnameverifier = f"grep -rnwzs --exclude='*.dex' -E {verifier_check} {sources} | wc -l"
    try:
        output = subprocess.check_output(cmd_check_hostnameverifier, shell=True).splitlines()
        if int(output[0]) > 0:
            total_matches += 1
    except subprocess.CalledProcessError as e:
        if e.returncode != 1:
            msg = "%s;%s;%s;NETWORK-3;hostname verifier functions grep error or not found" % (apk_hash, package_name, ct)
            logging.error(msg)
    except:
        msg = "%s;%s;%s;NETWORK-3;hostname verifier functions grep error or not found" % (apk_hash, package_name, ct)
        logging.error(msg)

    if net_config and total_matches == 0:
        total_matches = 1
        verdict = 'Needs Review'
    elif not net_config and low_target_sdk and total_matches == 0:
        total_matches = 1
        findings.append("%s;%s;NETWORK;NETWORK-3;%s;-" % (apk_hash, package_name, os.path.join(wdir, apk.replace(".apk", ""), "AndroidManifest.xml")))
    elif not net_config and not low_target_sdk or total_matches > 0:
        total_matches = 0
        verdict = 'PASS'
    else:
        total_matches = 0
    report["NETWORK-3"] = verdict
    fail_counts["NETWORK-3"] = total_matches
    print('NETWORK-3 successfully tested.')
    return [verdict, total_matches]
