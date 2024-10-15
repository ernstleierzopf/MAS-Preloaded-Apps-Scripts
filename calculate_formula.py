import sys
import yaml
import base64
import utils.formula as formula

method_config_path = sys.argv[1]
permissions_path = sys.argv[2]
fail_counts_path = sys.argv[3]
formula_path = sys.argv[4]

with open(method_config_path) as f:
    config = yaml.load(f, Loader=yaml.SafeLoader)
tests_list = [value.upper() for values in config["tests"].values() for value in values]
value = formula.calculate_formula(0.01, 0.01, tests_list, method_config_path, permissions_path, fail_counts_path)

with open(method_config_path) as f:
    config_string = f.read()
with open(formula_path, "w") as f:
    f.write("score;base64_method_config\n{:.4f};{}".format(value, base64.b64encode(config_string.encode("utf-8")).decode("utf-8")))
