from bs4 import BeautifulSoup
import json
from numpy import column_stack
import pandas as pd 
from pprint import pprint
import requests
import yaml

def test():
    with open('sigma_dict_pretty.json') as rules:
        rules0 = rules.read()
        rules1 = json.loads(rules0)
        aws_rules_methods = {}
        for k, v in rules1.items():
            if k == "cloud":
                for k0, v0 in v.items():
                    if k0 == "aws/cloudtrail":
                        for k2, v2 in v0.items():
                            detection = v2.get("detection")
                            selection = detection.get("selection")
                            tags = v2.get("tags")
                            if isinstance(selection, dict):
                                for k3, v3, in selection.items():
                                    if k3 == 'eventName':
                                        if isinstance(v3, str):
                                            if v3 not in aws_rules_methods.keys():
                                                aws_rules_methods.update({v3: [tags]})
                                            else:
                                                for tag in tags:
                                                    method = aws_rules_methods.get(v3)
                                                    if isinstance(method, dict):
                                                        for k4, v4 in method.items():
                                                            if tag not in v4:
                                                                v4.append(tag)
                                                        aws_rules_methods.update({v3: [v4]})
                                        if isinstance(v3, list):
                                            for k5 in v3:
                                                if k5 not in aws_rules_methods.keys():
                                                    aws_rules_methods.update({k5: [tags]})
                                                else:
                                                    for tag in tags:
                                                        method = aws_rules_methods.get(k5)
                                                        if isinstance(method, dict):
                                                            for k6, v6 in method.items():
                                                                if tag not in v6:
                                                                    v6.append(tag)
                                                            aws_rules_methods.update({k5: [v6] })
    with open('cloud_aws_dict.json', 'w') as fp:
        json.dump(aws_rules_methods, fp, indent=4)
    
                                    





if __name__=="__main__":
    test()