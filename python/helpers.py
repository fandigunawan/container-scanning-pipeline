import gitlab
import json
import git_helpers
import os
from pprint import pprint

gitlab_url = "https://dccscr.dsop.io"
gitlab_key = os.environ['GITLAB_KEY']

dccscr_project_id = 143

SAMPLE_IMAGE_NAME = "openjdk"
SAMPLE_IMAGE_VERSION = "1.8"

def main():
    proj = git_helpers.init(dccscr_project_id)
    # gl = git_helpers.get_all_filename_and_refs_json(proj)

    # print(get_all_the_things_json(proj, SAMPLE_IMAGE_NAME, SAMPLE_IMAGE_VERSION))

    print(git_helpers.get_all_filename_and_refs_json(proj))


class Vuln:
    vuln_id = ""
    vuln_desc = ""
    vuln_source = ""
    whitelist_source = ""
    status = ""
    approved_date = ""
    approved_by = ""
    justification = ""

    def __repr__(self):
        return "Vuln: " + self.vulnerability + " - " + self.vuln_source + " - " + self.whitelist_source + " - "+ self.status + " - " + self.approved_by

    def __str__(self):
        return "Vuln: " + self.vulnerability + " - " + self.vuln_source + " - " + self.whitelist_source + " - "+ self.status + " - " + self.approved_by

    def __init__(self, v):
        self.vulnerability = v['vulnerability']
        self.vuln_description = v['vuln_description']
        self.vuln_source = v['vuln_source']
        self.status = v['status']
        self.approved_date = v['approved_date']
        self.approved_by = v['approved_by']
        self.justification = v['justification']

    # def __init__(self, vid, desc, source, stat, date, by, just):
    #     self.vulnerability = vid
    #     self.vuln_description = desc
    #     self.vuln_source = source
    #     self.status = stat
    #     self.approved_date = date
    #     self.approved_by = by
    #     self.justification = just

    def set_whitelist_source(self, val):
        self.whitelist_source = val


class AnchoreGate:
    image_id = ""
    repo_tag = ""
    trigger_id = ""
    gate = ""
    trigger = ""
    check_output = ""
    gate_action = ""
    # whitelisted = ""
    policy_id = ""

    matched_rule_id = ""
    whitelist_id = ""
    whitelist_name = ""

    def __init__(self, g):
        self.image_id = g[0]
        self.repo_tag = g[1]
        self.trigger_id = g[2]
        self.gate = g[3]
        self.trigger = g[4]
        self.check_output = g[5]
        self.gate_action = g[6]
        # self.whitelisted = g[7]
        self.policy_id = g[8]

        if g[7]:
            self.matched_rule_id = g[7]['matched_rule_id']
            self.whitelist_id = g[7]['whitelist_id']
            self.whitelist_name = g[7]['whitelist_name']



# working
def get_all_the_things_json(proj, im_name, im_ver):
    first_call = git_helpers.get_whitelist_path_ref(proj, im_name, im_ver)

    if first_call:
        fn = first_call[0]
        ver = first_call[1]

        contents = git_helpers.get_whitelist_file_contents(proj, fn, ver)
        contents['complete_whitelist'] = []
        # contents['complete_whitelist'] = git_helpers.get_complete_whitelist_for_image(proj, im_name, im_ver)
        complete_wl = git_helpers.get_complete_whitelist_for_image(proj, im_name, im_ver)

        for x in complete_wl:
            contents['complete_whitelist'].append(x.__dict__)

        # contents['complete_whitelist'] = json.dumps(.__dict__)
        # app_json = json.dumps(contents, default=git_helpers.set_default)
        return json.dumps(contents)
    else:
        return im_name, im_ver, "not found."


if __name__ == "__main__":
    main()  # with if