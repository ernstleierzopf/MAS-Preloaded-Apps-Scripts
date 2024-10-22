import os
import sys
import yaml
import base64
import hashlib
import utils.formula as formula
import logging

method_config_path = sys.argv[1]
permissions_path = sys.argv[2]
fail_counts_path = sys.argv[3]
score_path = sys.argv[4]
all_scores_path = sys.argv[5]
firmware_image_path = sys.argv[6]

if not os.path.exists(permissions_path):
    logging.error("Permission path %s does not exist. Stopping.." % permissions_path)
    exit(1)

if not os.path.exists(fail_counts_path):
    logging.error("Fail counts path %s does not exist. Stopping.." % fail_counts_path)
    exit(1)

with open(method_config_path) as f:
    config = yaml.load(f, Loader=yaml.SafeLoader)
tests_list = [value.upper() for values in config["tests"].values() for value in values]
value = formula.calculate_formula(0.01, 0.01, tests_list, method_config_path, permissions_path, fail_counts_path)

with open(method_config_path) as f:
    config_string = f.read()
with open(score_path, "w") as f:
    f.write("SCORE;BASE64_METHOD_CONFIG\n{:.4f};{}".format(value, base64.b64encode(config_string.encode("utf-8")).decode("utf-8")))
if not os.path.exists(all_scores_path):
    with open(all_scores_path, "w") as f:
        f.write("FIRMWARE_HASH;FIRMWARE_NAME;SCORE;BASE64_METHOD_CONFIG\n")
sha256 = hashlib.sha256()
with open(firmware_image_path, "rb") as f:
    f_content = f.read()
sha256.update(f_content)
with open(all_scores_path, "a") as f:
    f.write("{};{};{:.4f};{}\n".format(sha256.hexdigest(), os.path.basename(firmware_image_path), value, base64.b64encode(config_string.encode("utf-8")).decode("utf-8")))
