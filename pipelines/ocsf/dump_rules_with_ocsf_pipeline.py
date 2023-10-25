from sigma_ocsf import ocsf_pipeline
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
import os 
import json

pipeline = ocsf_pipeline()
backend = SplunkBackend(pipeline)

sigma_rules_dict = {}

def dump_rules():
    repo_path = input("Input sigma rule path: ") or "rules"
    # replace_dict = input("Input replace dictionary containing key, value pairs of logsource and field mapping data: ") or "replace_dict.json"
    filenames = []
    for root, dirs, files in os.walk(repo_path):
        for filename in files:
            filenames.append((os.path.join(root, filename)))
        for dirname in dirs:
            filenames.append((os.path.join(root, dirname)))
    for i in filenames:
        if str(i).startswith("rules/cloud"):
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
