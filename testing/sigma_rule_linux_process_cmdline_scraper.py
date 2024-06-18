import csv
import json
import os
from pprint import pprint
import yaml

### Script to scrape linux 'process creation' and 'auditd' sigma rules from a local copy of the SigmaHQ "rules" directory. Outputs a csv file containing process and command line combinations and their respective description, level, mitre tags, and titles. 
### Assumes "rules" directory is located in the same directory as script
### Creates file titled "rule_meta.csv"

class SigmaRuleScrape:
    def __init__(self):
        self.dir_path = input("Input sigma rule path: ") or "rules"
        self.write_to_csv = input("Write json results to csv file in cwd? (y or n): ") or "n"
    
    def return_rule_meta(self):
        self.filenames = []
        self.rule_meta = []
        tactics = {
            "attack.reconnaissance": "TA0043",
            "attack.resource_development": "TA0042",
            "attack.initial_access": "TA0001",
            "attack.execution": "TA0002",
            "attack.persistence": "TA0003",
            "attack.privilege_escalation": "TA0004",
            "attack.defense_evasion": "TA0005",
            "attack.credential_access": "TA0006",
            "attack.discovery": "TA0007",
            "attack.lateral_movement": "TA0008",
            "attack.collection": "TA0009",
            "attack.command_and_control": "TA0011",
            "attack.exfiltration": "TA0010",
            "attack.impact": "TA0040"
            }
        dir_path  = self.dir_path
        for root, dirs, files in os.walk(dir_path):
            for filename in files:
                self.filenames.append((os.path.join(root, filename)))
            for dirname in dirs:
                self.filenames.append((os.path.join(root, dirname)))
            for i in self.filenames:
                if str(i).startswith("rules/linux/process_creation") or str(i).startswith("rules/linux/auditd"):
                    try:
                        if "proc_creation" in str(i):
                            with open(""+i, "r") as ry: 
                                yaml_load = yaml.safe_load(ry)
                            detection_d = yaml_load.get("detection")
                            tags_l = yaml_load.get("tags")
                            title = yaml_load.get("title")
                            description = yaml_load.get("description")
                            tags = {}
                            tid = []
                            tactic_id = []
                            process = []
                            level = yaml_load.get("level")
                            cmd = []
                            for tag in tags_l:
                                for tactic, id in tactics.items():
                                    if tactic == tag:
                                        tactic_id.append(id)
                                    else:
                                        continue
                                if str(tag).startswith("attack.t"):
                                    tid.append(tag)
                                else:
                                    continue
                            if len(tid) > 0:
                                for i in tid:
                                    for a in tactic_id:
                                        tags.update({a: i})
                            else:
                                if tactic_id not in tags.keys():
                                    tags.update({tactic_id: "None"})
                            for k, v in detection_d.items():
                                if k == "selection":
                                    if isinstance(v, dict):
                                        for k1, v1 in v.items():
                                            if k1 == "Image":
                                                if isinstance(v1, str):
                                                    process.append(v1)
                                                elif isinstance(v1, list):
                                                    for k3 in v1:
                                                        process.append(k3)  
                                                elif isinstance(v1, dict):
                                                    print(f'{v1} is a dict!')
                                            elif k1 == "Image|contains":
                                                if isinstance(v1, str):
                                                    p = "*" + str(v1) + "*"
                                                    process.append(p)
                                                elif isinstance(v1, list):
                                                    for k3 in v1:
                                                        p = "*" + str(k3) + "*"
                                                        process.append(p)  
                                                elif isinstance(v1, dict):
                                                    print(f'{v1} is a dict!')
                                            elif k1 == "Image|startswith":
                                                if isinstance(v1, str):
                                                    p = str(v1) + "*"
                                                    process.append(p)
                                                elif isinstance(v1, list):
                                                    for k3 in v1:
                                                        p = str(k3) + "*"
                                                        process.append(p)  
                                                elif isinstance(v1, dict):
                                                    print(f'{v1} is a dict!')
                                            elif k1 == "Image|endswith":
                                                if isinstance(v1, str):
                                                    p = "*" + str(v1)
                                                    process.append(p)
                                                elif isinstance(v1, list):
                                                    for k3 in v1:
                                                        p = "*" + str(k3)
                                                        process.append(p)  
                                                elif isinstance(v1, dict):
                                                    print(f'{v1} is a dict!')
                                            elif k1 == "CommandLine":
                                                if isinstance(v1, str):
                                                    cmd.append(v1)
                                                elif isinstance(v1, list):
                                                    for k3 in v1:
                                                        cmd.append(k3)  
                                                elif isinstance(v1, dict):
                                                    print(f'{v1} is a dict!')
                                            elif k1 == "CommandLine|contains":
                                                if isinstance(v1, str):
                                                    c = "*" + str(v1) + "*"
                                                    cmd.append(c)
                                                elif isinstance(v1, list):
                                                    for k3 in v1:
                                                        c = "*" + str(k3) + "*"
                                                        cmd.append(c)  
                                                elif isinstance(v1, dict):
                                                    print(f'{v1} is a dict!')
                                            elif k1 == "CommandLine|startswith":
                                                if isinstance(v1, str):
                                                    c = str(v1) + "*"
                                                    cmd.append(c)
                                                elif isinstance(v1, list):
                                                    for k3 in v1:
                                                        c = str(k3) + "*"
                                                        cmd.append(c)  
                                                elif isinstance(v1, dict):
                                                    print(f'{v1} is a dict!')
                                            elif k1 == "CommandLine|endswith":
                                                if isinstance(v1, str):
                                                    c = "*" + str(v1)
                                                    cmd.append(c)
                                                elif isinstance(v1, list):
                                                    for k3 in v1:
                                                        c = "*" + str(k3)
                                                        cmd.append(c)  
                                                elif isinstance(v1, dict):
                                                    print(f'{v1} is a dict!')
                                    if len(process) or len(cmd) > 0:
                                        self.rule_meta.append({
                                            "title": title,
                                            "description": description,
                                            "tags": tags,
                                            "level": level,
                                            "process": process,
                                            "cmdline": cmd
                                        }) 
                        elif "lnx_auditd" in str(i):
                            with open(""+i, "r") as ry: 
                                yaml_load = yaml.safe_load(ry)
                            detection_d = yaml_load.get("detection")
                            tags_l = yaml_load.get("tags")
                            title = yaml_load.get("title")
                            description = yaml_load.get("description")
                            tags = {}
                            tid = []
                            tactic_id = []
                            process = []
                            level = yaml_load.get("level")
                            cmd = []
                            for tag in tags_l:
                                for tactic, id in tactics.items():
                                    if tactic == tag:
                                        tactic_id.append(id)
                                    else:
                                        continue
                                if str(tag).startswith("attack.t"):
                                    tid.append(tag)
                                else:
                                    continue
                            if len(tid) > 0:
                                for i in tid:
                                    for a in tactic_id:
                                        tags.update({a: i})
                            else:
                                if tactic_id not in tags.keys():
                                    tags.update({tactic_id: "None"})
                            for k, v in detection_d.items():
                                if k == "selection":
                                    if isinstance(v, dict):
                                        for k1, v1 in v.items():
                                            if k1 == "name":
                                                if isinstance(v1, str):
                                                    process.append(v1)
                                                elif isinstance(v1, list):
                                                    for k3 in v1:
                                                        process.append(k3)  
                                                elif isinstance(v1, dict):
                                                    print(f'{v1} is a dict!')
                                            elif str(k1).startswith("a") and str(k1).endswith("0") or str(k1).endswith("1") or str(k1).endswith("2") or str(k1).endswith("3"):
                                                if isinstance(v1, str):
                                                    cmd.append(v1)
                                                elif isinstance(v1, list):
                                                    for k3 in v1:
                                                        cmd.append(k3)  
                                                elif isinstance(v1, dict):
                                                    print(f'{v1} is a dict!')
                                            elif str(k1).startswith("a") and str(k1).endswith("contains"):
                                                if isinstance(v1, str):
                                                    c = "*" + str(v1) + "*"
                                                    cmd.append(c)
                                                elif isinstance(v1, list):
                                                    for k3 in v1:
                                                        c = "*" + str(k3) + "*"
                                                        cmd.append(c)  
                                                elif isinstance(v1, dict):
                                                    print(f'{v1} is a dict!')
                                            elif str(k1).startswith("a") and str(k1).endswith("startswith"):
                                                if isinstance(v1, str):
                                                    c = str(v1) + "*"
                                                    cmd.append(c)
                                                elif isinstance(v1, list):
                                                    for k3 in v1:
                                                        c = str(k3) + "*"
                                                        cmd.append(c)  
                                                elif isinstance(v1, dict):
                                                    print(f'{v1} is a dict!')
                                            elif str(k1).startswith("a") and str(k1).endswith("endswith"):
                                                if isinstance(v1, str):
                                                    c = "*" + str(v1)
                                                    cmd.append(c)
                                                elif isinstance(v1, list):
                                                    for k3 in v1:
                                                        c = "*" + str(k3)
                                                        cmd.append(c)  
                                                elif isinstance(v1, dict):
                                                    print(f'{v1} is a dict!')
                                    if len(process) or len(cmd) > 0:
                                        self.rule_meta.append({
                                            "title": title,
                                            "description": description,
                                            "tags": tags,
                                            "level": level,
                                            "process": process,
                                            "cmdline": cmd
                                        }) 
                    except Exception as e:
                        pass
        return self.rule_meta
    
    def convert_json(self):
        self.json_rule_meta = json.dumps(self.rule_meta, indent = 2)
        return self.json_rule_meta
    
    def convert_csv(self):
        if self.write_to_csv == "y":
            headers = ['title', 'description', 'tags', 'level', 'process', 'cmdline']
            json_rule_meta = json.loads(self.json_rule_meta)
            with open(os.path.join(os.getcwd(), 'rule_meta.csv'), 'w', newline='\n') as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
                writer.writerows(json_rule_meta)

sigma_rule_scrape = SigmaRuleScrape()

results = sigma_rule_scrape.return_rule_meta()

json_results = sigma_rule_scrape.convert_json()

csv_results = sigma_rule_scrape.convert_csv()

if __name__=="__main__":
    print(json_results)
