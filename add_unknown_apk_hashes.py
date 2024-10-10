import os
import sys

apk_hashes = sys.argv[1]
all_apk_hashes = sys.argv[2]

with open(apk_hashes, "r") as f:
    lines = f.readlines()

all_lines = []
unknown_lines = []
if os.path.exists(all_apk_hashes):
    with open(all_apk_hashes, "r") as f:
        all_lines = f.readlines()

for line in lines:
    if line not in all_lines:
        unknown_lines.append(line)

with open(all_apk_hashes, "a") as f:
    f.writelines(unknown_lines)
