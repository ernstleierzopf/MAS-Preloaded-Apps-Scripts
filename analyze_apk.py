import os
import hashlib
import sys
import requests
import subprocess
import shutil
import json
import time
import yaml
import logging
from settings import RULES_SEMGREP_PATH
from utils.decompile_apktool import decompile as decompile_apk
from utils.decompile_jadx import decompile as decompile_jadx
from utils.auxiliar_functions import get_version_name, use_semgrep, get_script_version, check_package_name, get_suid_from_manifest, load_and_execute_methods
from utils.formula import extract_and_store_permissions

ADA_URL = "https://appdefense-dot-devsite-v2-prod-3p.appspot.com/directory/data/certs.json"
apk_dir_path = sys.argv[1]
all_apk_hashes = sys.argv[2]
apk_results = sys.argv[3]
all_apk_results = sys.argv[4]
apk_fail_counts = sys.argv[5]
all_apk_fail_counts = sys.argv[6]
apk_findings = sys.argv[7]
all_apk_findings = sys.argv[8]
apk_permissions = sys.argv[9]
all_apk_permissions = sys.argv[10]
results_header = "HASH;APP_NAME;VERSION_NAME;SCRIPT_VERSION;CODE-1;CODE-2;CRYPTO-1;CRYPTO-3;NETWORK-1;NETWORK-2;NETWORK-3;PLATFORM-2;PLATFORM-3;STORAGE-2"
fail_counts_header = "HASH;APP_NAME;VERSION_NAME;SCRIPT_VERSION;CODE_1;CODE_2;CRYPTO_1;CRYPTO_3;NETWORK_1;NETWORK_2;NETWORK_3;PLATFORM_2;PLATFORM_3;STORAGE_2"
findings_header = "HASH;APP_NAME;CATEGORY;TEST_ID;PATH;LINE"
permissions_header = "HASH;APP_NAME;PERMISSIONS"

all_lines = []
if os.path.exists(all_apk_hashes):
    with open(all_apk_hashes, "r") as f:
        all_lines = f.readlines()

apk_path = None
for path in os.listdir(apk_dir_path):
    if path.endswith(".apk"):
        apk_path = os.path.join(apk_dir_path, path)
        break

extracted_path = os.path.join(apk_dir_path, os.path.basename(apk_path).replace(".apk", ""))
ada_path = os.path.join(os.path.dirname(apk_path), "certs.json")
android_manifest_path = os.path.join(extracted_path, "AndroidManifest.xml")

sha256 = hashlib.sha256()
with open(apk_path, "rb") as f:
    f_content = f.read()
sha256.update(f_content)
searched_hash = sha256.hexdigest()

found = False
for line in all_lines:
    apk_hash = line.split(";")[1].replace("\n", "")
    if apk_hash == searched_hash:
        found = True
        break
if not found:
    # download ADA json
    response = requests.get(ADA_URL)
    with open(ada_path, "wb") as f:
        f.write(response.content)

    cwd = os.getcwd()
    semgrep = use_semgrep()
    script_version = get_script_version()
    version_name = get_version_name(extracted_path)
    with open('config/methods_config.yml') as f:
        config = yaml.load(f, Loader=yaml.SafeLoader)
    os.chdir(apk_dir_path)
    decompile_apk(apk_path, os.path.dirname(__file__))
    decompiled_dir = os.path.join(apk_dir_path, "decompiled")
    decompile_jadx(decompiled_dir, apk_path, os.path.dirname(__file__))
    os.chdir(cwd)

    try:
        response = subprocess.check_output('grep -or -E "https?:\\/\\/(www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{2,256}\\.[a-z]{2,4}\\b([-a-zA-Z0-9@:%_\\+.~#?&//=]*)" ' + decompiled_dir + ' --exclude-dir=resources --no-filename', shell=True)
        net2 = set(response.decode("utf-8").split("\n"))
        net2.remove("")
        net2 = [x + "\n" for x in net2]
    except subprocess.CalledProcessError:
        net2 = []
    with open(os.path.join(apk_dir_path, "net2.txt"), "w") as f:
        f.writelines(net2)

    try:
        response = subprocess.check_output('grep -or -E "http:\\/\\/(www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{2,256}\\.[a-z]{2,4}\\b([-a-zA-Z0-9@:%_\\+.~#?&//=]*)" ' + decompiled_dir + ' --exclude-dir=resources --no-filename', shell=True)
        http_net2 = set(response.decode("utf-8").split("\n"))
        http_net2.remove("")
        http_net2 = [x + "\n" for x in http_net2]
    except subprocess.CalledProcessError:
        http_net2 = []
    with open(os.path.join(apk_dir_path, "http_net2.txt"), "w") as f:
        f.writelines(http_net2)

    subprocess.check_output('cat ' + os.path.join(apk_dir_path, "net2.txt") + '| cut -d "/" -f 3 | sort | uniq > ' + os.path.join(apk_dir_path, "filtered_net2.txt"), shell=True)
    shutil.copy2(os.path.join(decompiled_dir, "resources", "AndroidManifest.xml"), android_manifest_path)
    package_name = check_package_name(extracted_path, os.path.basename(apk_path))

    internet = 0
    try:
        response = subprocess.check_output('cat ' + android_manifest_path + ' | grep -E "INTERNET|ACCESS_NETWORK_STATE|ACCESS_WIFI_STATE"', shell=True)
    except subprocess.CalledProcessError:
        internet = 1
    suid = 0
    try:
        response = subprocess.check_output('cat ' + android_manifest_path + ' | grep -Po "(?<=android:sharedUserId=)\\"[^\\"]+\\"" | sed \'s/\\"//g\'', shell=True)
    except subprocess.CalledProcessError:
        suid = 1

    with open(ada_path, 'r') as file:
        ada_data = json.load(file)
    certificates = ada_data.get("certificates", [])
    # initialize app values
    report = {"apk_hash": searched_hash, "app_name": package_name, "version_name": version_name,
              "script_version": script_version, "CODE-1": "PASS", "CODE-2": "PASS", "CRYPTO-1": "PASS",
              "CRYPTO-3": "PASS", "NETWORK-1": "PASS", "NETWORK-2": "PASS", "NETWORK-3": "PASS", "PLATFORM-2": "PASS",
              "PLATFORM-3": "PASS", "STORAGE-2": "PASS"}
    fail_counts = {"apk_hash": searched_hash, "app_name": package_name, "version_name": version_name,
                   "script_version": script_version, "CODE-1": 0, "CODE-2": 0, "CRYPTO-1": 0,
                   "CRYPTO-3": 0, "NETWORK-1": 0, "NETWORK-2": 0, "NETWORK-3": 0, "PLATFORM-2": 0, "PLATFORM-3": 0, "STORAGE-2": 0}
    findings = []
    # app_permissions = None
    # scanned = False
    # for certificate in certificates:
    #     if certificate.get("packageName") == package_name:
    #         app_permissions = extract_and_store_permissions(android_manifest_path)
    #         scanned = True

    # if not scanned:
    if semgrep:
        # semgrep scan
        app_results = {}
        if os.path.isdir(apk_dir_path):
            # analyze app
            app_name = os.path.basename(apk_dir_path)
            category_results = {}
            for category in os.listdir(RULES_SEMGREP_PATH):
                category_path = os.path.join(RULES_SEMGREP_PATH, category)
                if os.path.isdir(category_path):
                    print(f"Scanning OWASP MASTG category: {category} for {app_name}")
                    start_time = time.time()

                    all_findings = []
                    for testcase in os.listdir(category_path):
                        if testcase.endswith(".yaml"):
                            testcase_path = os.path.join(category_path, testcase)
                            # scan with semgrep
                            final_path = os.path.join(apk_dir_path, 'decompiled/sources/')
                            start_time = time.time()
                            cmd = ["semgrep", "--config", testcase_path, "--json", final_path, "--no-git-ignore"]
                            findings_list = []

                            try:
                                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                                findings = json.loads(result.stdout)

                                for finding in findings.get("results", []):
                                    check_id = finding.get("check_id", "N/A")
                                    path = finding.get("path", "N/A")
                                    start_line = finding.get("start", {}).get("line", "N/A")
                                    findings_list.append(finding)

                            except subprocess.CalledProcessError as e:
                                print(f"Semgrep encountered an error: {e}")
                            except Exception as e:
                                print(f"Unexpected error processing {rules_path}. Details: {e}")

                            elapsed_time = (time.time() - start_time) / 60
                            all_findings.extend(findings_list)
                    scan_time = (time.time() - start_time) / 60  # Convert to minutes
                    category_results[category] = (all_findings, scan_time)
            app_results[app_name] = category_results
            logging.error("SEMGREP TESTING IS NOT IMPLEMENTED!")
            #print(app_results)
            #print(category_results)
        # if app_results:
        #     write_to_database(app_results, searched_hash, package_name, version_name, script_version, uuid_execution)
        if not app_results:
            print("No findings detected across all apps.")
    else:
        # check app
        print("Starting scanning process...")
        # Check if the application has internet permissions or if another application with the same SUID has internet permissions
        # check network applies
        out_suid_string = get_suid_from_manifest(extracted_path)
        applies = False

        if suid == 1:
            applies = True
        elif suid == 0:
            report["NETWORK-1"] = "NA"
            report["NETWORK-2"] = "NA"
            report["NETWORK-3"] = "NA"
            fail_counts["NETWORK-1"] = 0
            fail_counts["NETWORK-2"] = 0
            fail_counts["NETWORK-3"] = 0

        all_params = {'wdir': apk_dir_path, 'apk': os.path.basename(apk_path), 'apk_hash': searched_hash, 'package_name': package_name,
                      'report': report, 'fail_counts': fail_counts, 'findings': findings}
        load_and_execute_methods(config['tests'], all_params, applies)
        app_permissions = extract_and_store_permissions(android_manifest_path)
        if not os.path.exists(all_apk_results):
            with open(all_apk_results, "w") as f:
                f.write(results_header + "\n")
        if not os.path.exists(apk_results):
            with open(apk_results, "w") as f:
                f.write(results_header + "\n")
        if not os.path.exists(all_apk_fail_counts):
            with open(all_apk_fail_counts, "w") as f:
                f.write(fail_counts_header + "\n")
        if not os.path.exists(apk_fail_counts):
            with open(apk_fail_counts, "w") as f:
                f.write(fail_counts_header + "\n")
        if not os.path.exists(all_apk_findings):
            with open(all_apk_findings, "w") as f:
                f.write(findings_header + "\n")
        if not os.path.exists(apk_findings):
            with open(apk_findings, "w") as f:
                f.write(findings_header + "\n")
        if not os.path.exists(all_apk_permissions):
            with open(all_apk_permissions, "w") as f:
                f.write(permissions_header + "\n")
        if not os.path.exists(apk_permissions):
            with open(apk_permissions, "w") as f:
                f.write(permissions_header + "\n")

        values = []
        for key in list(report.keys()):
            values.append(report[key])
        with open(all_apk_results, "a") as f:
            f.write(";".join(values) + "\n")
        with open(apk_results, "a") as f:
            f.write(";".join(values) + "\n")

        values = []
        for key in list(fail_counts.keys()):
            values.append(str(fail_counts[key]))
        with open(all_apk_fail_counts, "a") as f:
            f.write(";".join(values) + "\n")
        with open(apk_fail_counts, "a") as f:
            f.write(";".join(values) + "\n")

        with open(all_apk_findings, "a") as f:
            for finding in findings:
                f.write(finding + "\n")
        with open(apk_findings, "a") as f:
            for finding in findings:
                f.write(finding + "\n")

        with open(all_apk_permissions, "a") as f:
            f.write(searched_hash + ";" + os.path.basename(apk_path) + ";" + app_permissions + "\n")
        with open(apk_permissions, "a") as f:
            f.write(searched_hash + ";" + os.path.basename(apk_path) + ";" + app_permissions + "\n")

        with open(all_apk_hashes, "a") as f:
            f.write(os.path.basename(apk_path) + ";" + searched_hash + "\n")

else:  # already analyzed - add results from all files to this result
    if not os.path.exists(apk_results):
        with open(apk_results, "w") as f:
            f.write(results_header + "\n")
    if not os.path.exists(apk_fail_counts):
        with open(apk_fail_counts, "w") as f:
            f.write(fail_counts_header + "\n")
    if not os.path.exists(apk_findings):
        with open(apk_findings, "w") as f:
            f.write(findings_header + "\n")
    if not os.path.exists(apk_permissions):
        with open(apk_permissions, "w") as f:
            f.write(permissions_header + "\n")

    results = []
    with open(all_apk_results, "r") as f:
        lines = f.readlines()
    for line in lines:
        if line.split(";")[0] == searched_hash:
            results.append(line)
    with open(apk_results, "a") as f:
        f.writelines(results)

    results = []
    with open(all_apk_fail_counts, "r") as f:
        lines = f.readlines()
    for line in lines:
        if line.split(";")[0] == searched_hash:
            results.append(line)
    with open(apk_fail_counts, "a") as f:
        f.writelines(results)

    results = []
    with open(all_apk_findings, "r") as f:
        lines = f.readlines()
    for line in lines:
        if line.split(";")[0] == searched_hash:
            results.append(line)
    with open(apk_findings, "a") as f:
        f.writelines(results)

    results = []
    with open(all_apk_permissions, "r") as f:
        lines = f.readlines()
    for line in lines:
        if line.split(";")[0] == searched_hash:
            results.append(line)
    with open(apk_permissions, "a") as f:
        f.writelines(results)
