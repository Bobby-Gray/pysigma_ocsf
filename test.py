from bs4 import BeautifulSoup
import json
from numpy import column_stack
import pandas as pd 
from pprint import pprint
import requests
import yaml

def test():
    with open('sigma_dict1.json') as rules:
        rules0 = rules.read()
        rules1 = json.loads(rules0)

        with open('sigma_dict_pretty.json', 'w') as fp:
            json.dump(rules1, fp, indent=2)
                                    





if __name__=="__main__":
    test()