import json
import os
import re
from pprint import pprint
import yaml


class RuleRepoStrReplace:
    def __init__(self):
        self.repo_path = input("Input sigma rule path: ") or "rules"
        self.replace_dict = input("Input replace dictionary containing key, value pairs of logsource and field mapping data: ") or "replace_dict.json"
        self.filenames = []
        for root, dirs, files in os.walk(self.repo_path):
            for filename in files:
                self.filenames.append((os.path.join(root, filename)))
            for dirname in dirs:
                self.filenames.append((os.path.join(root, dirname)))
    
    def return_logsource_meta(self):
        filenames = self.filenames
        self.logsource_meta = {}
        for i in filenames:
            if str(i).endswith(".yml"):
                try:
                    with open(""+i, "r") as ry: 
                        yaml_load = yaml.safe_load(ry)
                    title = yaml_load.get("title")
                    logsource = yaml_load.get("logsource")
                    if isinstance(logsource, dict):
                        for k, v in logsource.items():
                            if isinstance(k, str) and isinstance(v, str) and not k == "definition":
                                if k not in self.logsource_meta.keys():
                                    self.logsource_meta.update({k: []})
                                if v not in self.logsource_meta[k]:
                                    self.logsource_meta[k].append(v)
                    else:
                        print(f'unhandled: {i}')
                    
                except Exception as e:
                    print(e)     
        pprint(self.logsource_meta, indent=2) 
        return self.logsource_meta

    # replace_dict = open(self.replace_dict, 'r')

     # def replace_all(text, dic):
    #     for i, j in dic.items():
    #         text = re.sub(r"\b%s\b"%i, j, text) 
    #         # r"\b%s\b"% enables replacing by whole word matches only
    #     return text

        # data = replace_all(data,match)
        # print(data) 

rule_repo_str_replace = RuleRepoStrReplace()

logsource_meta = rule_repo_str_replace.return_logsource_meta()

if __name__=="__main__":
    pprint('Done!')