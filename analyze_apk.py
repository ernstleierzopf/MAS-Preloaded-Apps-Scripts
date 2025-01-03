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

logging.basicConfig(format='{levelname:^5s} - {message:s}', style='{', level=logging.INFO)
logging.getLogger().setLevel(logging.INFO)

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
base_path = sys.argv[11]
method_config_path = os.path.join(base_path, "config/methods_config.yml")
results_header = "Hash;App-name;Version-name;Script-version;Code-1;Code-2;Crypto-1;Crypto-3;Network-1;Network-2;Network-3;Platform-2;Platform-3;Storage-2"
fail_counts_header = "Hash;App-name;Version-name;Script-version;Code-1;Code-2;Crypto-1;Crypto-3;Network-1;Network-2;Network-3;Platform-2;Platform-3;Storage-2"
findings_header = "Hash;App-name;Category;Test-ID;Path;Line"
permissions_header = "Hash;App-name;Permissions"

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
    apk_hash = line.split(";")[0].replace("\n", "")
    if apk_hash == searched_hash:
        found = True
        break
if not found:
    # download ADA json
    response = requests.get(ADA_URL)
    with open(ada_path, "wb") as f:
        f.write(response.content)

    cwd = os.getcwd()
    semgrep = use_semgrep(method_config_path)
    script_version = get_script_version(method_config_path)
    with open(method_config_path) as f:
        config = yaml.load(f, Loader=yaml.SafeLoader)
    os.chdir(apk_dir_path)
    logging.info("Starting analysis of %s." % os.path.basename(apk_path))
    decompile_apk(apk_path)
    if not os.path.exists(extracted_path):
        logging.error("Extracted APK path does not exist. Stopping..")
        exit(1)
    decompiled_dir = os.path.join(apk_dir_path, "decompiled")
    decompile_jadx(decompiled_dir, apk_path)
    if not os.path.exists(decompiled_dir):
        logging.error("Decompiled APK path does not exist. Stopping..")
        exit(1)
    os.chdir(cwd)

    try:
        response = subprocess.check_output('grep -or -E "https?:\\/\\/(www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{2,256}\\.[a-z]{2,4}\\b([-a-zA-Z0-9@:%_\\+.~#?&//=]*)" "' + decompiled_dir + '" --exclude-dir=resources --no-filename', shell=True)
        net2 = set(response.decode("utf-8").split("\n"))
        net2.remove("")
        net2 = [x + "\n" for x in net2]
    except subprocess.CalledProcessError:
        net2 = []
    with open(os.path.join(apk_dir_path, "net2.txt"), "w") as f:
        f.writelines(net2)

    try:
        response = subprocess.check_output('grep -or -E "http:\\/\\/(www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{2,256}\\.[a-z]{2,4}\\b([-a-zA-Z0-9@:%_\\+.~#?&//=]*)" "' + decompiled_dir + '" --exclude-dir=resources --no-filename', shell=True)
        http_net2 = set(response.decode("utf-8").split("\n"))
        http_net2.remove("")
        http_net2 = [x + "\n" for x in http_net2]
    except subprocess.CalledProcessError:
        http_net2 = []
    with open(os.path.join(apk_dir_path, "http_net2.txt"), "w") as f:
        f.writelines(http_net2)

    subprocess.check_output('cat "' + os.path.join(apk_dir_path, "net2.txt") + '" | cut -d "/" -f 3 | sort | uniq > "' + os.path.join(apk_dir_path, "filtered_net2.txt") + '"', shell=True)
    shutil.copy2(os.path.join(decompiled_dir, "resources", "AndroidManifest.xml"), android_manifest_path)
    version_name = get_version_name(extracted_path)
    package_name = check_package_name(extracted_path, os.path.basename(apk_path))

    internet = 0
    try:
        response = subprocess.check_output('cat "' + android_manifest_path + '" | grep -E "INTERNET|ACCESS_NETWORK_STATE|ACCESS_WIFI_STATE"', shell=True)
    except subprocess.CalledProcessError:
        internet = 1
    suid = 0
    try:
        response = subprocess.check_output('cat "' + android_manifest_path + '" | grep -Po "(?<=android:sharedUserId=)\\"[^\\"]+\\"" | sed \'s/\\"//g\'', shell=True)
    except subprocess.CalledProcessError:
        suid = 1

    with open(ada_path, 'r') as file:
        ada_data = json.load(file)
    certificates = ada_data.get("certificates", [])
    # initialize app values
    report = {"apk_hash": searched_hash, "app_name": package_name, "version_name": version_name,
              "script_version": script_version, "Code-1": "PASS", "Code-2": "PASS", "Crypto-1": "PASS",
              "Crypto-3": "PASS", "Network-1": "PASS", "Network-2": "PASS", "Network-3": "PASS", "Platform-2": "PASS",
              "Platform-3": "PASS", "Storage-2": "PASS"}
    fail_counts = {"apk_hash": searched_hash, "app_name": package_name, "version_name": version_name,
                   "script_version": script_version, "Code-1": 0, "Code-2": 0, "Crypto-1": 0,
                   "Crypto-3": 0, "Network-1": 0, "Network-2": 0, "Network-3": 0, "Platform-2": 0, "Platform-3": 0, "Storage-2": 0}
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
                                    finding["path"] = path.replace(apk_dir_path + "/", "")
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
            report["Network-1"] = "NA"
            report["Network-2"] = "NA"
            report["Network-3"] = "NA"
            fail_counts["Network-1"] = 0
            fail_counts["Network-2"] = 0
            fail_counts["Network-3"] = 0

        all_params = {'wdir': apk_dir_path, 'apk': os.path.basename(apk_path), 'apk_hash': searched_hash, 'package_name': package_name,
                      'report': report, 'fail_counts': fail_counts, 'findings': findings}
        load_and_execute_methods(config['tests'], all_params, applies)
        findings = [x.replace(apk_dir_path, os.path.basename(apk_dir_path)) for x in findings]
        app_permissions = extract_and_store_permissions(android_manifest_path)
        if not os.path.exists(all_apk_results) or os.stat(all_apk_results).st_size == 0:
            with open(all_apk_results, "w") as f:
                f.write(results_header + "\n")
        if not os.path.exists(apk_results):
            with open(apk_results, "w") as f:
                f.write(results_header + "\n")
        if not os.path.exists(all_apk_fail_counts) or os.stat(all_apk_fail_counts).st_size == 0:
            with open(all_apk_fail_counts, "w") as f:
                f.write(fail_counts_header + "\n")
        if not os.path.exists(apk_fail_counts):
            with open(apk_fail_counts, "w") as f:
                f.write(fail_counts_header + "\n")
        if not os.path.exists(all_apk_findings) or os.stat(all_apk_findings).st_size == 0:
            with open(all_apk_findings, "w") as f:
                f.write(findings_header + "\n")
        if not os.path.exists(apk_findings):
            with open(apk_findings, "w") as f:
                f.write(findings_header + "\n")
        if not os.path.exists(all_apk_permissions) or os.stat(all_apk_permissions).st_size == 0:
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
            f.write(searched_hash + ";" + os.path.basename(apk_path) + "\n")

else:  # already analyzed - add results from all files to this result
    logging.info("Analysis results for %s found. Reusing existing results." % os.path.basename(apk_path))
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
