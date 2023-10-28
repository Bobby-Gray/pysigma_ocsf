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
            pprint(f'Subdirectories found for given repo, attempting to recursively collect rule files.')
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
        return self.rules
    
    def parse_rule_yaml(self):
        self.cat_rules = self.rules
        for cat0, yaml_url0 in self.rules.items():
            if isinstance(yaml_url0, str):
                yaml_raw_url0 = yaml_url0.replace("/tree/", "/raw/")
                url0_response = requests.get(yaml_raw_url0)
                yaml0 = url0_response.content.decode("utf-8")
                yaml0_load = yaml.safe_load(yaml0)
                title0 = {}
                title0 = yaml0_load.get("title")
                id0 = {}
                id0 = yaml0_load.get("id")
                status0 = {}
                status0 = yaml0_load.get("description")
                description0 = {}
                description0 = yaml0_load.get("description")
                references0 = {}
                references0 = yaml0_load.get("references")
                author0 = {}
                author0 = yaml0_load.get("author")
                date0 = {}
                date0 = yaml0_load.get("date")
                modified0 = {}
                modified0 = yaml0_load.get("modified")
                tags0 = {}
                tags0 = yaml0_load.get("tags")
                logsource0 = {}
                logsource0 = yaml0_load.get("logsource")
                detection0 = {}
                detection0 = yaml0_load.get("detection")
                falsepositives0 = {}
                falsepositives0 = yaml0_load.get("falsepositives")
                level0 = {}
                level0 = yaml0_load.get("level")
                url0 = yaml_url0
                self.rules[cat0] = {
                    "title": title0,
                    "id": id0,
                    "status": status0,
                    "description": description0,
                    "references": references0,
                    "author": author0,
                    "date": date0,
                    "modified": modified0,
                    "tags": tags0,
                    "logsource": logsource0,
                    "detection": detection0,
                    "falsepositives": falsepositives0,
                    "level": level0,
                    "url": url0
                    }
            if isinstance(yaml_url0, dict):
                for cat1, yaml_url1 in yaml_url0.items():
                    if isinstance(yaml_url1, str):
                        yaml_raw_url1 = yaml_url1.replace("/tree/", "/raw/")
                        url1_response = requests.get(yaml_raw_url1)
                        yaml1 = url1_response.content.decode("utf-8")
                        yaml1_load = yaml.safe_load(yaml1)
                        title1 = {}
                        title1 = yaml1_load.get("title")
                        id1 = {}
                        id1 = yaml1_load.get("id")
                        status1 = {}
                        status1 = yaml1_load.get("description")
                        description1 = {}
                        description1 = yaml1_load.get("description")
                        references1 = {}
                        references1 = yaml1_load.get("references")
                        author1 = {}
                        author1 = yaml1_load.get("author")
                        date1 = {}
                        date1 = yaml1_load.get("date")
                        modified1 = {}
                        modified1 = yaml1_load.get("modified")
                        tags1 = {}
                        tags1 = yaml1_load.get("tags")
                        logsource1 = {}
                        logsource1 = yaml1_load.get("logsource")
                        detection1 = {}
                        detection1 = yaml1_load.get("detection")
                        falsepositives1 = {}
                        falsepositives1 = yaml1_load.get("falsepositives")
                        level1 = {}
                        level1 = yaml1_load.get("level")
                        url1 = yaml_url1
                        yaml_url0[cat1] = {
                            "title": title1,
                            "id": id1,
                            "status": status1,
                            "description": description1,
                            "references": references1,
                            "author": author1,
                            "date": date1,
                            "modified": modified1,
                            "tags": tags1,
                            "logsource": logsource1,
                            "detection": detection1,
                            "falsepositives": falsepositives1,
                            "level": level1,
                            "url": url1
                            }
                    if isinstance(yaml_url1, dict):
                        for cat2, yaml_url2 in yaml_url1.items():
                            if isinstance(yaml_url2, str):
                                yaml_raw_url2 = yaml_url2.replace("/tree/", "/raw/")
                                url2_response = requests.get(yaml_raw_url2)
                                yaml2 = url2_response.content.decode("utf-8")
                                yaml2_load = yaml.safe_load(yaml2)
                                title2 = {}
                                title2 = yaml2_load.get("title")
                                id2 = {}
                                id2 = yaml2_load.get("id")
                                status2 = {}
                                status2 = yaml2_load.get("description")
                                description2 = {}
                                description2 = yaml2_load.get("description")
                                references2 = {}
                                references2 = yaml2_load.get("references")
                                author2 = {}
                                author2 = yaml2_load.get("author")
                                date2 = {}
                                date2 = yaml2_load.get("date")
                                modified2 = {}
                                modified2 = yaml2_load.get("modified")
                                tags2 = {}
                                tags2 = yaml2_load.get("tags")
                                logsource2 = {}
                                logsource2 = yaml2_load.get("logsource")
                                detection2 = {}
                                detection2 = yaml2_load.get("detection")
                                falsepositives2 = {}
                                falsepositives2 = yaml2_load.get("falsepositives")
                                level2 = {}
                                level2 = yaml2_load.get("level")
                                url2 = yaml_url2
                                yaml_url1[cat2] = {
                                    "title": title2,
                                    "id": id2,
                                    "status": status2,
                                    "description": description2,
                                    "references": references2,
                                    "author": author2,
                                    "date": date2,
                                    "modified": modified2,
                                    "tags": tags2,
                                    "logsource": logsource2,
                                    "detection": detection2,
                                    "falsepositives": falsepositives2,
                                    "level": level2,
                                    "url": url2
                                    }
                                continue
                            if isinstance(yaml_url2, dict):
                                for cat3, yaml_url3 in yaml_url2.items():
                                    if isinstance(yaml_url3, str):
                                        yaml_raw_url3 = yaml_url3.replace("/tree/", "/raw/")
                                        url3_response = requests.get(yaml_raw_url3)
                                        yaml3 = url3_response.content.decode("utf-8")
                                        yaml3_load = yaml.safe_load(yaml3)
                                        title3 = {}
                                        title3 = yaml3_load.get("title")
                                        id3 = {}
                                        id3 = yaml3_load.get("id")
                                        status3 = {}
                                        status3 = yaml3_load.get("description")
                                        description3 = {}
                                        description3 = yaml3_load.get("description")
                                        references3 = {}
                                        references3 = yaml3_load.get("references")
                                        author3 = {}
                                        author3 = yaml3_load.get("author")
                                        date3 = {}
                                        date3 = yaml3_load.get("date")
                                        modified3 = {}
                                        modified3 = yaml3_load.get("modified")
                                        tags3 = {}
                                        tags3 = yaml3_load.get("tags")
                                        logsource3 = {}
                                        logsource3 = yaml3_load.get("logsource")
                                        detection3 = {}
                                        detection3 = yaml3_load.get("detection")
                                        falsepositives3 = {}
                                        falsepositives3 = yaml3_load.get("falsepositives")
                                        level3 = {}
                                        level3 = yaml3_load.get("level")
                                        url3 = yaml_url3
                                        yaml_url2[cat3] = {
                                            "title": title3,
                                            "id": id3,
                                            "status": status3,
                                            "description": description3,
                                            "references": references3,
                                            "author": author3,
                                            "date": date3,
                                            "modified": modified3,
                                            "tags": tags3,
                                            "logsource": logsource3,
                                            "detection": detection3,
                                            "falsepositives": falsepositives3,
                                            "level": level3,
                                            "url": url3
                                            }
                                        continue
                                    if isinstance(yaml_url3, dict):
                                        for cat4, yaml_url4 in yaml_url3.items():
                                            if isinstance(yaml_url4, str):
                                                yaml_raw_url4 = yaml_url4.replace("/tree/", "/raw/")
                                                url4_response = requests.get(yaml_raw_url4)
                                                yaml4 = url4_response.content.decode("utf-8")
                                                yaml4_load = yaml.safe_load(yaml4)
                                                title4 = {}
                                                title4 = yaml4_load.get("title")
                                                id4 = {}
                                                id4 = yaml4_load.get("id")
                                                status4 = {}
                                                status4 = yaml4_load.get("description")
                                                description4 = {}
                                                description4 = yaml4_load.get("description")
                                                references4 = {}
                                                references4 = yaml4_load.get("references")
                                                author4 = {}
                                                author4 = yaml4_load.get("author")
                                                date4 = {}
                                                date4 = yaml4_load.get("date")
                                                modified4 = {}
                                                modified4 = yaml4_load.get("modified")
                                                tags4 = {}
                                                tags4 = yaml4_load.get("tags")
                                                logsource4 = {}
                                                logsource4 = yaml4_load.get("logsource")
                                                detection4 = {}
                                                detection4 = yaml4_load.get("detection")
                                                falsepositives4 = {}
                                                falsepositives4 = yaml4_load.get("falsepositives")
                                                level4 = {}
                                                level4 = yaml4_load.get("level")
                                                url4 = yaml_url4
                                                yaml_url3[cat4] = {
                                                    "title": title4,
                                                    "id": id4,
                                                    "status": status4,
                                                    "description": description4,
                                                    "references": references4,
                                                    "author": author4,
                                                    "date": date4,
                                                    "modified": modified4,
                                                    "tags": tags4,
                                                    "logsource": logsource4,
                                                    "detection": detection4,
                                                    "falsepositives": falsepositives4,
                                                    "level": level4,
                                                    "url": url4
                                                    }
                                                continue
                                            if isinstance(yaml_url4, dict):
                                                for cat5, yaml_url5 in yaml_url4.items():
                                                    if isinstance(yaml_url5, str):
                                                        yaml_raw_url5 = yaml_url5.replace("/tree/", "/raw/")
                                                        url5_response = requests.get(yaml_raw_url5)
                                                        yaml5 = url5_response.content.decode("utf-8")
                                                        yaml5_load = yaml.safe_load(yaml5)
                                                        title5 = {}
                                                        title5 = yaml5_load.get("title")
                                                        id5 = {}
                                                        id5 = yaml5_load.get("id")
                                                        status5 = {}
                                                        status5 = yaml5_load.get("description")
                                                        description5 = {}
                                                        description5 = yaml5_load.get("description")
                                                        references5 = {}
                                                        references5 = yaml5_load.get("references")
                                                        author5 = {}
                                                        author5 = yaml5_load.get("author")
                                                        date5 = {}
                                                        date5 = yaml5_load.get("date")
                                                        modified5 = {}
                                                        modified5 = yaml5_load.get("modified")
                                                        tags5 = {}
                                                        tags5 = yaml5_load.get("tags")
                                                        logsource5 = {}
                                                        logsource5 = yaml5_load.get("logsource")
                                                        detection5 = {}
                                                        detection5 = yaml5_load.get("detection")
                                                        falsepositives5 = {}
                                                        falsepositives5 = yaml5_load.get("falsepositives")
                                                        level5 = {}
                                                        level5 = yaml5_load.get("level")
                                                        url5 = yaml_url5
                                                        yaml_url4[cat5] = {
                                                            "title": title5,
                                                            "id": id5,
                                                            "status": status5,
                                                            "description": description5,
                                                            "references": references5,
                                                            "author": author5,
                                                            "date": date5,
                                                            "modified": modified5,
                                                            "tags": tags5,
                                                            "logsource": logsource5,
                                                            "detection": detection5,
                                                            "falsepositives": falsepositives5,
                                                            "level": level5,
                                                            "url": url5
                                                            }
                                                        continue
                                                    if isinstance(yaml_url5, dict):
                                                        print(f'Need deeper loop! @ {yaml_url5}')
        with open('sigma_dict.json', 'w') as fp:
            json.dump(self.rules, fp)
        return self.rules


sigma_ocsf_rule_conversion = SigmaOcsfRuleConversion()

sigma_categories = sigma_ocsf_rule_conversion.get_sigma_categories()

sigma_rules = sigma_ocsf_rule_conversion.get_sigma_rules()

rule_yaml = sigma_ocsf_rule_conversion.parse_rule_yaml()

if __name__=="__main__":
    pprint('Done!')