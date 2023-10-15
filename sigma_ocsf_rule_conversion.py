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

    def get_sigma_categories(self):
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
            for rule_cat, sub_cat in self.rules_dirs.items():
                if isinstance(sub_cat, dict):
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
        pprint(f'self.rules_dirs: {self.rules_dirs}')
        return self.rules_dirs

    def get_sigma_rules(self):
        self.rules = self.rules_dirs
        for cat0, rule_url0 in self.rules.items():
            if isinstance(rule_url0, str):
                url0_response = requests.get(rule_url0)
                url0_json = json.loads(url0_response.text)
                url0_tree = url0_json['payload']['tree']['items']
                url0_rule_urls = {}
                for url0_url in url0_tree:
                    url0_type = url0_url['contentType']
                    url0_name = str(url0_url['name'])
                    url0_path = url0_url['path']
                    if url0_type == 'file' and url0_name.endswith('.yml'):
                        url0 = self.repo_url.replace("rules", url0_path)
                        url0_rule_urls.update({url0_name : url0})
                if len(url0_rule_urls) > 0:
                    self.rules.update({cat0 : url0_rule_urls})
                else:
                    pass
            if isinstance(rule_url0, dict):
                for cat1, rule_url1 in rule_url0.items():
                    if isinstance(rule_url1, str):
                        url1_response = requests.get(rule_url1)
                        url1_json = json.loads(url1_response.text)
                        url1_tree = url1_json['payload']['tree']['items']
                        url1_rule_urls = {}
                        for url1_url in url1_tree:
                            url1_type = url1_url['contentType']
                            url1_name = str(url1_url['name'])
                            url1_path = url1_url['path']
                            if url1_type == 'file' and url1_name.endswith('.yml'):
                                url1 = self.repo_url.replace("rules", url1_path)                           
                                url1_rule_urls.update({url1_name : url1})
                        if len(url1_rule_urls) > 0:
                            rule_url0.update({cat1 : url1_rule_urls})
                        else:
                            pass
                    if isinstance(rule_url1, dict):
                        for cat2, rule_url2 in rule_url1.items():
                            if isinstance(rule_url2, str):
                                url2_response = requests.get(rule_url2)
                                url2_json = json.loads(url2_response.text)
                                url2_tree = url2_json['payload']['tree']['items']
                                url2_rule_urls = {}
                                for url2_url in url2_tree:
                                    url2_type = url2_url['contentType']
                                    url2_name = str(url2_url['name'])
                                    url2_path = url2_url['path']
                                    if url2_type == 'file' and url2_name.endswith('.yml'):
                                        url2 = self.repo_url.replace("rules", url2_path)   
                                        url2_rule_urls.update({url2_name : url2})
                                if len(url2_rule_urls) > 0:
                                    rule_url1.update({cat2 : url2_rule_urls})
                                else:
                                    pass
                            if isinstance(rule_url2, dict):
                                print(f'More!\n\n')
                                break 
        pprint(f'self.rules: {self.rules}')
        return self.rules

sigma_ocsf_rule_conversion = SigmaOcsfRuleConversion()

sigma_categories = sigma_ocsf_rule_conversion.get_sigma_categories()

sigma_rules = sigma_ocsf_rule_conversion.get_sigma_rules()

if __name__=="__main__":
    pprint(f'Done!')