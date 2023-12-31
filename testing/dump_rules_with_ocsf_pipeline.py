from .sigma_ocsf import ocsf_pipeline
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
import os 

pipeline = ocsf_pipeline()
backend = SplunkBackend(pipeline)

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
        if str(i).startswith("rules/cloud/gcp"):
            try:
                with open(""+i, "r") as ry: 
                    rules = SigmaCollection.from_yaml(ry)
                    print("Result: " + "\n".join(backend.convert(rules)))
            except Exception as e:
                print(e)    

if __name__=="__main__":
    dump_rules()
