import os
import hashlib
import sys

apk_hashes = sys.argv[1]
apks_path = "apks"

with open(apk_hashes, "w") as hash_file:
    for root, dirs, files in os.walk(apks_path, topdown=True):
        for filename in files:
            file_path = os.path.join(root, filename)
            sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                f_content = f.read()
            sha256.update(f_content)
            hash_file.write("%s;%s\n" % (filename, sha256.hexdigest()))
