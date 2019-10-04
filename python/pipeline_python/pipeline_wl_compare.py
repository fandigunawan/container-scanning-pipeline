import gitlab
import sys
import json
from bs4 import BeautifulSoup
import re
import os


gitlab_url = "https://dccscr.dsop.io"
dccscr_project_id = 143
WHITELIST_FILENAME_IDENTIFIER = "greylist"
gitlab_key = os.environ['PYTHON_GITLAB_KEY']


def main():
    # RENAME_ME_PLEASE(IMAGE_NAME,
    #                  IMAGE_VER,
    #                  path_to_oscap_file,
    #                  path_to_oval_file,
    #                  path_to_twistlock_file,
    #                  path_to_anchore_sec_file,
    #                  path_to_anchore_gates_file)

    x = pipeline_whitelist_compare(sys.argv[1],
                               sys.argv[2],
                               sys.argv[3],
                               sys.argv[4],
                               sys.argv[5],
                               sys.argv[6],
                               sys.argv[7])

    print(x)
    os.exit(x)


def pipeline_whitelist_compare(image_name, image_version, oscap, oval, twist, anc_sec, anc_gates):
    proj = init(dccscr_project_id)
    if not does_image_exist(proj, image_name, image_version):
        print(image_name, image_version)
        return "Image Does Not Exist"

    image_whitelist = get_complete_whitelist_for_image(proj, image_name, image_version)

    wl_set = set()
    for image in image_whitelist:
        if image.status == "approved":
            wl_set.add(image.vulnerability)

    print("Whitelist Set: ", wl_set)
    print("Whitelist Set Length: ", len(wl_set))

    vuln_set = set()

    oscap_cves = get_oscap_fails(oscap)
    # print("Oscap Set Length: ", len(oscap_cves))
    for oscap in oscap_cves:
        vuln_set.add(oscap['identifiers'])

    oval_cves = get_oval(oval)
    # print("Oval Set Length: ", len(oval_cves))
    for oval in oval_cves:
        vuln_set.add(oval['ref'])

    tl_cves = get_twistlock_full(twist)
    # print("Twistlock Set Length: ", len(tl_cves))
    for tl in tl_cves:
        vuln_set.add(tl['cve'])

    anchore_cves = get_anchore_full(anc_sec)
    # print("Anchore Sec Set Length: ", len(anchore_cves))
    for anc in anchore_cves:
        vuln_set.add(anc['I DONT KNOW WHAT GOES HERE'])

    # anchore_gates = report_helpers.get_anchore_gates_full(anc_gates)
    # print("Anchore Gates Set Length: ", len(anchore_cves))
    # for anc in anchore_gates:
    #     print(anc.__dict__)
    #     # vuln_set.add(anc['aofasf'])

    print("Vuln Set: ", vuln_set)
    print("Vuln Set Length: ", len(vuln_set))

    if vuln_set in wl_set:
        print("ALL VULNERABILITIES WHITELISTED")
        return 0
    else:
        print("NON-WHITELISTED VULNERABILITIES FOUND")
        delta = vuln_set.difference(wl_set)
        return (delta)
        # print("DELTA" + str(delta))
        # print("DELTA SIZE: ", len(delta))


def get_twistlock_full(twistlock_file):
    with open(twistlock_file) as twistlock_json_file:
        json_data = json.load(twistlock_json_file)[0]
        twistlock_data = json_data['info']['cveVulnerabilities']
        cves = []

        for x in twistlock_data:
            cve = x['cve']
            cvss = x['cvss']
            desc = x['description']
            exploit = x['exploit']
            id = x['id']
            link = x['link']
            packageName = x['packageName']
            packageVersion = x['packageVersion']
            severity = x['severity']
            status = x['status']
            type = x['type']
            vecStr = x['vecStr']

            ret = {
                'cve': cve,
                'cvss': cvss,
                'desc': desc,
                'exploit': exploit,
                'id': id,
                'link': link,
                'packageName': packageName,
                'packageVersion': packageVersion,
                'severity': severity,
                'status': status,
                'type': type,
                'vecStr': vecStr
            }

            # print(ret)

            cves.append(ret)
    return cves


def get_anchore_full(anchore_file):
    with open(anchore_file) as af:
        json_data = json.load(af)

        anchore_data = json_data['data']
        cves = []
        for x in anchore_data:
            tag = x[0]
            cve = x[1]
            severity = x[2]
            vuln = x[3]
            fix = x[4]
            url = x[5]

            # print(cve)

            ret = {
                'tag': tag,
                'cve': cve,
                'severity': severity,
                'vuln': vuln,
                'fix': fix,
                'url': url
            }

            cves.append(cve)
        return cves


def get_oval(oval_file):
    oscap = open(oval_file, 'r')
    soup = BeautifulSoup(oscap, 'html.parser')
    results_bad = soup.find_all("tr", class_=["resultbadA", "resultbadB"])
    results_good = soup.find_all("tr", class_=["resultgoodA", "resultgoodB"])

    cves = []
    for x in results_bad: # + results_good:
        id = x.find("td")
        result = id.find_next_sibling("td")
        cls = result.find_next_sibling("td")
        y = x.find_all(target='_blank')
        references = set()
        for t in y:
            references.add(t.text)
        title = cls.find_next_sibling("td").find_next_sibling("td")

        for ref in references:
            cves.append(ref)
    return cves


def get_oscap_fails(oscap_file):
    with open(oscap_file) as of:
        soup = BeautifulSoup(of, 'html.parser')
        divs = soup.find('div', id="result-details")


        scan_date = soup.find("th", text='Finished at')
        finished_at = scan_date.find_next_sibling("td").text
        # print(finished_at.text)
        regex = re.compile('.*rule-detail-fail.*')
        id_regex = re.compile('.*rule-detail-.*')
        fails = divs.find_all("div", {"class": regex})
        all = divs.find_all("div", {"class": id_regex})

        cces = []
        for x in fails:
            title = x.find("h3", {"class": "panel-title"}).text
            table = x.find("table", {"class": "table table-striped table-bordered"})

            ruleid = table.find("td", text="Rule ID").find_next_sibling("td").text
            result = table.find("td", text="Result").find_next_sibling("td").text
            severity = table.find("td", text="Severity").find_next_sibling("td").text
            ident = table.find("td", text="Identifiers and References").find_next_sibling("td")
            if ident.find("abbr"):
                identifiers = ident.find("abbr").text

            references = ident.find_all("a", href=True)
            refs = []
            for j in references:
                refs.append(j.text)

            desc = table.find("td", text="Description").find_next_sibling("td").text
            rationale = table.find("td", text="Rationale").find_next_sibling("td").text

            ret = {
                'title': title,
                # 'table': table,
                'ruleid': ruleid,
                'result': result,
                'severity': severity,
                'identifiers': identifiers,
                'refs': refs,
                'desc': desc,
                'rationale': rationale,
                'scanned_date': finished_at
            }
            cces.append(ret)
        return cces


def does_image_exist(proj, im_name, im_tag):
    all_wls = get_whitelist_filenames(proj)

    for item in all_wls:
        print(item['basename'], item['filename'])
        wl = get_whitelist_file_contents(proj, item['filename'], item['ref'])
        if wl['image_name'] == im_name and wl['image_tag'] == im_tag:
            return True
    return False


def get_whitelist_filenames(project):
    wl_fns = project.search('blobs', 'authorized_approvers')
    return wl_fns


def get_whitelist_file_contents(proj, item_path, item_ref):
    f = proj.files.get(file_path=item_path, ref=item_ref)
    try:
        contents = json.loads(f.decode())
    except ValueError as error:
        print("JSON object issue: %s") % error
    return contents


def get_complete_whitelist_for_image(proj, im_name, im_tag):
    all_wls = get_whitelist_filenames(proj)
    total_wl = []

    for item in all_wls:
        contents = get_whitelist_file_contents(proj, item['filename'], item['ref'])

        par_image = contents['image_parent_name']
        par_tag = contents['image_parent_tag']

        if contents['image_name'] == im_name and contents['image_tag'] == im_tag:
            for x in get_whitelist_for_image(proj, im_name, im_tag):
                x.set_whitelist_source(im_name)
                total_wl.append(x)

            if len(par_image) > 0 and len(par_tag) > 0:
                for y in get_complete_whitelist_for_image(proj, par_image, par_tag):
                    y.set_whitelist_source(par_image)
                    total_wl.append(y)

    return total_wl


def get_whitelist_for_image(proj, im_name, im_tag):
    all_wls = get_whitelist_filenames(proj)
    wl = []

    for item in all_wls:
        contents = get_whitelist_file_contents(proj, item['filename'], item['ref'])
        if contents['image_name'] == im_name and contents['image_tag'] == im_tag:
            for v in contents['whitelisted_vulnerabilities']:
                tar = Vuln(v)
                wl.append(tar)
    return wl


def init(pid):
    gl = gitlab.Gitlab(gitlab_url, private_token=gitlab_key)
    # gl = gitlab.Gitlab(gitlab_url) #Anonymous Auth
    #gl.auth()
    return gl.projects.get(pid)

def get_group(gid):
    gl = gitlab.Gitlab(gitlab_url, private_token=gitlab_key)
    return gl.groups.get(gid)


def set_default(obj):
    if isinstance(obj, set):
        return list(obj)
    raise TypeError


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


if __name__ == "__main__":
    main()  # with if
