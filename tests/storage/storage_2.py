"""STORAGE-2 - MASTG-TEST-0001"""

import subprocess
import datetime
import logging
import os


def check(wdir, apk, apk_hash, package_name, report, fail_counts, findings):
    """
    Checks for WRITE_EXTERNAL_STORAGE in AndroidManifest.xml file.
    If it is not found, it is a PASS
    """
    output_write_external = 0
    cmd = "grep -n --exclude='*.dex' -iE WRITE_EXTERNAL_STORAGE %s" % os.path.join(wdir, apk.replace(".apk", ""), 'AndroidManifest.xml')
    ct = datetime.datetime.now()

    try:
        output = subprocess.check_output(cmd, shell=True).splitlines()
        if output:
            output_write_external += 1   
            match_line = output[0].decode().strip().split(':', 1)[0]
            findings.append("%s;%s;STORAGE;STORAGE-2;%s;%s" % (apk_hash, package_name, os.path.join(wdir, apk.replace(".apk", ""), 'AndroidManifest.xml'), match_line))
    except subprocess.CalledProcessError as e:
        if e.returncode != 1:
            msg = "%s;%s;%s;STORAGE-2;grep for WRITE_EXTERNAL_STORAGE permission failed. File not found" % (apk_hash, package_name, ct)
            logging.error(msg)
    except:
        msg = "%s;%s;%s;STORAGE-2;grep for WRITE_EXTERNAL_STORAGE permission failed. File not found" % (apk_hash, package_name, ct)
        logging.error(msg)
    total_matches = 0
    verdict = 'FAIL'
    if output_write_external >= 1:
        storage_functions = ["getExternalStorageDirectory", "getExternalFilesDir"]
        for i in storage_functions:
            sources = os.path.join(wdir, "decompiled", "sources")
            cmd = f"grep -rnws --exclude='*.dex' -E {i} {sources}"
            set_matches = set()
            try:
                output = subprocess.check_output(cmd, shell=True).splitlines()
                if len(output) > 0:
                    for match in output:
                        match_str = match.decode()
                        try:
                            if '.java' in match_str:
                                match_file = match_str.split(":")[0]
                                match_line = match_str.split(":")[1] 
                                set_matches.add(match_file)
                                findings.append("%s;%s;STORAGE;STORAGE-2;%s;%s" % (apk_hash, package_name, match_file, match_line))
                            else:             
                                set_matches.add(match_str)
                                findings.append("%s;%s;STORAGE;STORAGE-2;%s;-" % (apk_hash, package_name, match_str))
                        except:
                            msg = "%s;%s;%s;STORAGE-2;It was not possible to get match_file or match_line" % (apk_hash, package_name, ct)
                            logging.error(msg)
                total_matches += len(set_matches)
            except subprocess.CalledProcessError as e:
                if e.returncode != 1:
                    msg = "%s;%s;%s;STORAGE-2;grep command failed for %s" % (apk_hash, package_name, ct, i)
                    logging.error(msg)
            except:
                msg = "%s;%s;%s;STORAGE-2;grep command failed for %s" % (apk_hash, package_name, ct, i)
                logging.error(msg)
        if total_matches == 0:
            verdict = 'PASS'
    elif output_write_external == 0:
        verdict = 'PASS'
    report["STORAGE-2"] = verdict
    fail_counts["STORAGE-2"] = total_matches
    print('STORAGE-2 successfully tested.')
    return [verdict, total_matches]
