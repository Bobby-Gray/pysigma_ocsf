from sigma_ocsf import ocsf_pipeline
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
import os 
import json

# Test script utilizing the ocsf pipeline and splunk backend. 
# This script will dump a json dictionary file, sigma_rules_dict.json, of rule names with their respective directory paths as keys and splunk searches as the values. 
#   Configured to be ran from within the same folder as sigma_ocsf.py
#   Requires a rules directory containing sigma rules. 
#   To limit to a specific directory/path, include an if statement for i before the try loop. 
#       e.g., if str(i).startswith("rules/cloud"):
#   Defaults to "rules" and will prepend any containing folder structure to the rule name.

pipeline = ocsf_pipeline()
backend = SplunkBackend(pipeline)

sigma_rules_dict = {}
def dump_rules():
    repo_path = input("Input sigma rule path: ") or "rules"
    filenames = []
    for root, dirs, files in os.walk(repo_path):
        for filename in files:
            filenames.append((os.path.join(root, filename)))
        for dirname in dirs:
            filenames.append((os.path.join(root, dirname)))
    for i in filenames:
            try:
                with open(""+i, "r") as ry: 
                    rules = SigmaCollection.from_yaml(ry)
                    rule = "".join(backend.convert(rules))
                    print("Result: " + "\n".join(backend.convert(rules)))
                    sigma_rules_dict.update({i: rule})
            except Exception as e:
                print(e)    

if __name__=="__main__":
    dump_rules()
    with open('sigma_rules_dict.json', 'w') as fp:
        json.dump(sigma_rules_dict, fp, indent=2)
