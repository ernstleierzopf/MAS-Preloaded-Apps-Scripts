"""PLATFORM-3 - MASTG-TEST-0028"""

import xml.etree.ElementTree as ET
import re, os


def check(wdir, apk, apk_hash, package_name, report, fail_counts, findings):
    """
    Extract custom url from the application.
    It extracts the scheme and the path defined. However, for this version it counts the number of custom URL scheme found
    to filter out those applications that have no custom URL in place.
    """
    verdict = 'PASS'
    manifest_path = os.path.join(wdir, apk.replace(".apk", ""), 'AndroidManifest.xml')
    custom_urls = 0

    with open(manifest_path, 'r') as file:
        xml_data = file.read()
    pattern = r'android:scheme="([^"]+)"'
    scheme_values = re.findall(pattern, xml_data)
    for value in scheme_values:
        if value != 'http' and value != 'https' and value != '' and value is not None:
            custom_urls = custom_urls + 1
    if custom_urls > 0:
        verdict = 'Needs Review'
    report["Platform-3"] = verdict
    fail_counts["Platform-3"] = custom_urls
    print('Platform-3 successfully tested.')
    return [verdict, custom_urls]
