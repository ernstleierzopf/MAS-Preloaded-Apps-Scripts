import os
import hashlib
import sys

apks_path = sys.argv[1]
apk_hashes = sys.argv[2]

with open(apk_hashes, "w") as hash_file:
    for root, dirs, files in os.walk(apks_path, topdown=True):
        for filename in files:
            file_path = os.path.join(root, filename)
            sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                f_content = f.read()
            sha256.update(f_content)
            hash_file.write("%s;%s\n" % (sha256.hexdigest(), filename))
