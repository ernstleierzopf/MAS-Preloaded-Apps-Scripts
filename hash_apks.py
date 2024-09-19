import os
import hashlib

apk_hashes = "apk_hashes.csv"

with open(apk_hashes, "w") as hash_file:
    for root, dirs, files in os.walk(walk_dir, topdown=True):
        for filename in files:
            file_path = os.path.join(root, filename)
            sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                f_content = f.read()
            sha256.update(f_content)
            hash_file.write("%s;%s\n" % (filename, sha256.hexdigest()))
