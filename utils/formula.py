import xml.etree.ElementTree as ET
from math import prod
import sys
sys.path.append('./')
from db import database_utils
# from settings import SUID_SYSTEM
import yaml

# Scoring dictionary

def extract_SUID(tree):
    root = tree.getroot()

    shared_user_id = root.get('{http://schemas.android.com/apk/res/android}sharedUserId')
    return shared_user_id

def extract_and_store_permissions(android_manifest_path):
    tree = ET.parse(android_manifest_path)
    root = tree.getroot()
    suid = extract_SUID(tree)
    all_perms = set()
    android_ns = 'http://schemas.android.com/apk/res/android'

    for elem in root.iter():
        if elem.tag == 'permission' or elem.tag == 'uses-permission':
            name = elem.get(f'{{{android_ns}}}name')
            if name:
                all_perms.add(name)
    permissions_from_app = ','.join(str(x) for x in all_perms)
    return permissions_from_app


# def extract_and_store_permissions(apk_hash, package_name, wdir, uuid_execution):
    # wdir = wdir+"/base/AndroidManifest.xml"
    # tree = ET.parse(wdir)
    # root = tree.getroot()
    # suid = extract_SUID(tree)
    # all_perms = set()
    # android_ns = 'http://schemas.android.com/apk/res/android'

    # # Extract permissions
    # for elem in root.iter():
    #     if elem.tag == 'permission' or elem.tag == 'uses-permission':
    #         name = elem.get(f'{{{android_ns}}}name')
    #         if name:
    #             all_perms.add(name)

    # # if suid == SUID_SYSTEM:
    # #     perms_config = get_all_permissions()
    # #     all_perms.update(perms_config)

    # # Print the permissions and scores
    # permissions_from_app = ','.join(str(x) for x in all_perms)  #This is to upload the permissions to the table
    # database_utils.insert_values_permissions(apk_hash, package_name, permissions_from_app, uuid_execution)
    # if suid is not None:
    #     database_utils.update_values_permissions_add_suid(apk_hash, suid, uuid_execution)

#FORMULA IS:
# All apps permission shall be extracted prior to formula calculation
def get_m_value(perm, tests, permissions_lists, fail_counts_path):
    total_fails = 0
    with open(fail_counts_path) as f:
        lines = f.readlines()[1:]
    for i, permissions_list in enumerate(permissions_lists):
        if perm in permissions_list:
            records = [x.replace("\n", "") for x in lines[i].split(";")[4:]]
            for r in records:
                total_fails += int(r)
    return total_fails


'''
get_risk returns the risk associated to a permission, if that app holds a "risky" permission.
'''
def get_risk(p, permissions, method_config_path):
    scoring = get_scoring(method_config_path)
    if p in permissions:
        return scoring[p]
    else:
        return 0
'''
get_value_k returns the number of apps that holds permission p
'''
def get_value_k(perm, permissions_lists):
    total_apps = 0
    for permissions_list in permissions_lists:
        if perm in permissions_list:
            total_apps += 1
    return total_apps

def calculate_formula(Constant1, Constant2, tests, method_config_path, permissions_path, fail_counts_path):
    result = 0
    all_permissions = get_all_permissions(method_config_path)
    with open(permissions_path) as f:
        records = f.readlines()
    records = [record.split(";") for record in records]
    permissions_lists = []
    for row in records[1:]:
        permissions_list = get_permissions_list(row[2].replace("\n", ""))
        permissions_lists.append(permissions_list)
    for p in all_permissions:
        risk = get_risk(p, all_permissions, method_config_path)
        value_k = get_value_k(p, permissions_lists)
        M = get_m_value(p, tests, permissions_lists, fail_counts_path)
        term = risk * (1 - ((1 - Constant1) ** value_k) * ((1 - Constant2) ** M))
        result += term
    formula_value = round(result, 4)
    sum_weights = get_sum_weights(method_config_path)
    risk_score = (formula_value / sum_weights) * 100
    return risk_score


def get_android_version(method_config_path):
    try:
        with open(method_config_path) as f:
            config = yaml.load(f, Loader=yaml.SafeLoader)
        android_version = int(config.get("androidVersion", 0))
        return android_version
    except:
        print("Error while getting android version from config file.")
        return 0


def get_all_permissions(method_config_path):
    android_version = get_android_version(method_config_path)
    with open(method_config_path) as f:
        config = yaml.load(f, Loader=yaml.SafeLoader)
    permissions_list = []
    if config['permissions'][android_version]:
        permissions_list = list(config['permissions'][android_version].keys())
    return permissions_list

def get_scoring(method_config_path):
    android_version = get_android_version(method_config_path)
    with open(method_config_path) as f:
        config = yaml.load(f, Loader=yaml.SafeLoader)
    permissions_weights_dict = {}
    if config['permissions'][android_version]:
        permissions_weights_dict = {permission: data['weight'] for permission, data in config['permissions'][android_version].items()}
    return permissions_weights_dict

def get_permissions_list(permissions_str):
    if permissions_str:
        permissions_list = [element.strip() for element in permissions_str.split(",")] if permissions_str else []
        return permissions_list
    return []

def get_sum_weights(method_config_path):

    android_version = get_android_version(method_config_path)

    with open('config/methods_config.yml') as f:
        config = yaml.load(f, Loader=yaml.SafeLoader)

    total_weight = 0

    permissions = config.get('permissions', {})
    if android_version in permissions:
        version_permissions = permissions[android_version] 
        for key, value in version_permissions.items():
            total_weight += value.get('weight', 0)
    else:
        print('The Android version you have specified in the config file does not have an associated permissions list.')

    return total_weight
