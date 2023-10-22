from bs4 import BeautifulSoup
from collections.abc import MutableMapping
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
        gcp_rules_methods = {}
        for k, v in rules1.items():
            if k == "cloud":
                for k0, v0 in v.items():
                    if k0 == "gcp":
                        for k1, v1 in v0.items():
                            if k1 == "audit":
                                for k2, v2 in v1.items():
                                    detection = v2.get("detection")
                                    selection = detection.get("selection")
                                    tags = v2.get("tags")
                                    for k3, v3, in selection.items():
                                        if str(k3).endswith("|startswith"):
                                            print(k3)        


if __name__=="__main__":
    test()