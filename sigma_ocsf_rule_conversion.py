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
        self.rules_dirs = {}
        for entry in tree:
            entry_type = entry['contentType']
            if entry_type == 'directory':
                self.rules_dirs.update({str(entry['name']) : self.repo_url + '/' + str(entry['name'])})
            else:
                pass
        if len(self.rules_dirs) > 0:
            pprint(self.rules_dirs)
        else:
            print(f'No subdirectories found in given repo.')

    def get_sigma_rules(self):
        if len(self.rules_dirs) > 0:
            for cat, dir in self.rules_dirs.items():
                cat_response = requests.get(dir)
                cat_json = json.loads(cat_response.content)
                cat_tree = cat_json['payload']['tree']['items']
                dirs = {}
                for cat_dir in cat_tree:
                    entry_type = cat_dir['contentType']
                    if entry_type == 'directory':
                        dirs.update({str(cat_dir['name']) : self.repo_url + '/' + cat + '/' + str(cat_dir['name'])})
                if len(dirs) > 0:
                    self.rules_dirs.update({cat : dirs})
                else:
                    self.rules_dirs.update({cat : {cat : dir}})
            pprint(self.rules_dirs)
            for rule_cat, sub_cat in self.rules_dirs.items():
                for sub, url in sub_cat.items():
                    sub_response = requests.get(url)
                    sub_json = json.loads(sub_response.content)
                    sub_tree = sub_json['payload']['tree']['items']
                    sub_dirs = {}
                    for sub_dir in sub_tree:
                        sub_type = sub_dir['contentType']
                        if sub_type == 'directory':
                            sub_dirs.update({str(sub_dir['name']) : self.repo_url + '/' + rule_cat + '/' + sub + '/' + str(sub_dir['name'])})
                    if len(sub_dirs) > 0:
                        sub_cat.update({sub : sub_dirs})
                    else:
                        sub_cat.update({sub : url})
            pprint(self.rules_dirs)

            

sigma_rules_dirs = SigmaOcsfRuleConversion()

sigma_rules = sigma_rules_dirs.get_sigma_rules()

if __name__=="__main__":
    pprint(f'ran: {sigma_rules}')