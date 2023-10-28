import json
from pprint import pprint
import requests
import yaml


class SearchBuilder: 
    def __init__(self):
        self.rules_json = input("Enter rules_dict.json file") or 'aws_gcp_rules_dict.json'
        with open(self.rules_json) as rules_json:
            rules_r = rules_json.read()
            self.rules = json.loads(rules_r)

    def gather_search_type_counts(self):
        eq_selection = 0
        eq_selection_us = 0
        selection_and = 0
        keywords = 0
        one_of = 0
        all_of = 0
        parenthesis = 0
        not_field = 0
        not_field_and_field = 0
        eq_not_selection_field = 0
        field_or_field = 0
        field_or_field_and_field = 0
        field_or_all_of_field = 0
        field_and_field = 0
        field_and_field_and_field = 0
        field_and_not_field = 0
        field_and_1_of_field = 0
        unhandled = []

        for k, v in self.rules.items():
            detection = v.get("detection")
            condition = detection.get("condition")
            if str(condition) == "selection":
                eq_selection += 1
            elif str(condition).startswith("selection_") and " " not in str(condition):
                eq_selection_us += 1
            elif str(condition).startswith("selection and "):
                selection_and += 1
            elif str(condition) == "keywords":
                keywords += 1
            elif str(condition).startswith("1 of "):
                one_of += 1
            elif str(condition).startswith("all of "):
                all_of += 1 
            elif "(" and ")" in str(condition):
                parenthesis += 1
            elif str(condition).startswith("not ") and len(str(condition).split(" ")) == 2:
                not_field += 1
            elif str(condition).startswith("not ") and " and " in str(condition) and len(str(condition).split(" ")) == 4:
                not_field_and_field += 1
            elif " " not in str(condition):
                eq_not_selection_field += 1 
            elif " or " in str(condition) and len(str(condition).split(" ")) == 3:
                field_or_field += 1 
            elif " or " and " and " in str(condition) and len(str(condition).split(" ")) == 5:
                field_or_field_and_field += 1 
            elif " and " in str(condition) and len(str(condition).split(" ")) == 3:
                field_and_field += 1 
            elif " and " in str(condition) and len(str(condition).split(" and ")) == 3:
                field_and_field_and_field += 1 
            elif " and not " in str(condition) and len(str(condition).split(" and not ")) == 2:
                field_and_not_field += 1 
            elif " and 1 of" in str(condition) and len(str(condition).split(" and 1 of")) == 2:
                field_and_1_of_field += 1 
            elif " or all of " in str(condition) and len(str(condition).split(" or all of ")) == 2:
                field_or_all_of_field += 1 
            else:
                unhandled.append(condition)
        print(f'eq_selection: {eq_selection} \neq_selection_us: {eq_selection_us} \nselection_and: {selection_and} \nkeywords: {keywords} \none_of: {one_of} \nall_of: {all_of} \nparenthesis: {parenthesis} \nnot_field: {not_field} \neq_not_selection_field: {eq_not_selection_field} \nfield_or_field: {field_or_field} \nfield_or_field_and_field: {field_or_field_and_field} \nfield_or_all_of_field: {field_or_all_of_field} \nfield_and_field: {field_and_field} \nfield_and_field_and_field: {field_and_field_and_field} \nfield_and_not_field: {field_and_not_field} \nfield_and_1_of_field: {field_and_1_of_field} \nunhandled_conditions: {unhandled}')

    def parse_searches(self):
        self.searches = {}
        for k, v in self.rules.items():
            logsource = v.get("logsource")
            detection = v.get("detection")
            selection = detection.get("selection")
            condition = detection.get("condition")
            tags = v.get("tags")
            if str(condition) == "selection":
                if isinstance(selection, dict):
                    for ks, vs in selection.items():
                        if isinstance(vs, str):
                            if str(ks).endswith("|contains"):
                                ks_split = str(ks).split("|contains")
                                search  = ks_split[0] + "=" + '"*' + str(vs) + '*"'
                                self.searches.update({k: {search}})
                            elif str(ks).endswith("|startswith"):
                                ks_split = str(ks).split("|startswith")
                                search  = ks_split[0] + "=" + '"' + str(vs) + '*"'
                                self.searches.update({k: {search}})
                            elif str(ks).endswith("|endswith"):
                                ks_split = str(ks).split("|endswith")
                                search  = ks_split[0] + "=" + '"*' + str(vs) + '"'
                                self.searches.update({k: {search}})
                            else:
                                search  = str(ks) + "=" + '"' + str(vs) + '"'
                                self.searches.update({k: {search}})
                        if isinstance(vs, list):
                            if str(ks).endswith("|contains"):
                                s_or = []
                                search = ""
                                ks_split = str(ks).split("|contains")
                                for xs in vs:
                                    s_or.append(ks_split[0] + "=" + '"*' + str(xs) + '*"')
                                for ss_or in s_or:
                                    search += str(ss_or) + " OR "
                                search = str(search).rstrip(" OR ")
                                self.searches.update({k: {search}})
                            elif str(ks).endswith("|startswith"):
                                s_or = []
                                search = ""
                                ks_split = str(ks).split("|startswith")
                                for xs in vs:
                                    s_or.append(ks_split[0] + "=" + '"' + str(xs) + '*"')
                                for ss_or in s_or:
                                    search += str(ss_or) + " OR "
                                search = str(search).rstrip(" OR ")
                                self.searches.update({k: {search}})
                            elif str(ks).endswith("|endswith"):
                                s_or = []
                                search = ""
                                ks_split = str(ks).split("|endswith")
                                for xs in vs:
                                    s_or.append(ks_split[0] + "=" + '"*' + str(xs) + '"')
                                for ss_or in s_or:
                                    search += str(ss_or) + " OR "
                                search = str(search).rstrip(" OR ")
                                self.searches.update({k: {search}})
                            else:
                                s_or = []
                                search = ""
                                for xs in vs:
                                    s_or.append(ks + "=" + '"' + str(xs) + '"')
                                for ss_or in s_or:
                                    search += str(ss_or) + " OR "
                                search = str(search).rstrip(" OR ")
                                self.searches.update({k: {search}})
                if isinstance(selection, list):
                    print("list")
        pprint(self.searches, indent=4)
        return self.searches

        # else:
        #     print(condition)
    # print(f'selection: \n contains_count: {contains_count} \n startswith_count: {startswith_count} \n endswith_count: {endswith_count} \n equals_field_count: {equals_field_count} \nnot_selection: {not_selection}')
                    
search_builder = SearchBuilder()

search_type_counts = search_builder.gather_search_type_counts()
parse_searches = search_builder.parse_searches()