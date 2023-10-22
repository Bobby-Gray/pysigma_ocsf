from re import I
from traceback import print_tb
from bs4 import BeautifulSoup
from collections.abc import MutableMapping
import json
from numpy import column_stack
import pandas as pd 
from pprint import pprint
import requests
import yaml

rules_only = {}

def test(rules_json):
    for k, v in rules_json.items():
        yield k
        if str(k).endswith(".yml"):
            rules_only.update({k: v})
        if isinstance(v, dict):
            yield from test(v)

with open('sigma_dict_pretty.json') as rules:
        rules_r = rules.read()
        rules_json = json.loads(rules_r)

for x in test(rules_json):
    print("working!")
    

if __name__=="__main__":
    test(rules_json)
    with open('rules_dict.json', 'w') as fp:
        json.dump(rules_only, fp, indent=2)