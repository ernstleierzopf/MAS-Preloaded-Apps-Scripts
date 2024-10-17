import subprocess
import sys
import os
import logging
from settings import PATH_APKTOOL


def decompile(app_path):
    command = ["java", "-jar", PATH_APKTOOL, "d", app_path]
    try:
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(timeout=180)
        if stderr is not None:
            logging.error("apktool had an error when extracting {}: {}".format(app_path, stderr))
        # Output is not displayed
        process.wait(timeout=300)
    except Exception as e:
        # Retry with another command:
        retry_command = ["java", "-jar", PATH_APKTOOL, "d", "-f", "--no-res", app_path]
        try:
            process_retry = subprocess.Popen(retry_command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            for line in process_retry.stdout:
                if 'Exception in thread "main" brut.androlib.AndrolibException: Invalid chunk type:' in line:
                    print('APKTOOL ERROR: An attempt has been made to decompile an .apk that does not qualify as an application.', end='\n')
                elif 'W: Cant find 9patch chunk in file' in line:
                    modified_line = line.replace("W:", "APKTOOL WARNING:")
                    print(modified_line, end='\n')
                elif 'I:' in line:
                    modified_line = line.replace("I:", "APKTOOL INFO:")
                    print(modified_line, end='')
            process_retry.wait(timeout=300)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            print("APKTOOL ERROR:", e)


if __name__ == "__main__":
    app = os.path.join(sys.argv[1])
    decompile(app)
