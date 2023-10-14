from bs4 import BeautifulSoup
import json
from pprint import pprint
import requests
import yaml

class SigmaOcsfRuleConversion:
    def __init__(self):
        self.repo_url = input("Input sigma rule repo url: ") or "https://github.com/SigmaHQ/sigma/tree/master/rules"
        repo_response = requests.get(self.repo_url)
        repo_json = json.loads(repo_response.content)
        tree = repo_json['payload']['tree']['items']
        idx = 0
        rules_dirs = {}
        for entry in tree:
            for k in entry.items():
                if k[0] == 'name':
                    rules_dirs.update({str(k[1]) : self.repo_url + '/' + str(k[1])})
                else:
                    pass
        print(rules_dirs)
            

sigma_ocsf_rule_conversion = SigmaOcsfRuleConversion()

if __name__=="__main__":
    pprint(f'ran: {sigma_ocsf_rule_conversion}')