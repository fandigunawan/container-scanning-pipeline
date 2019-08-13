import os
import urllib.request
import tarfile
import json
from bs4 import BeautifulSoup
import re
import pprint

main_dir = "/downloads";
test_report = "https://s3-us-gov-west-1.amazonaws.com/dsop-pipeline-artifacts/testing/container-scan-reports/redhat/ubi7/latest/2019-08-06T224510.448_1007/ubi7-latest-reports-signature.tar.gz"

def main():
    result = do_all_the_things(test_report)
    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(result)


def do_all_the_things(url):
    fp = download_tarball(url)
    folder_name = extract_tarball(fp)
    os.remove(fp)

    oscap = main_dir + "/" + folder_name + "/openscap/report.html"
    oval = main_dir + "/" + folder_name + "/openscap/report-cve.html"
    twistlock = main_dir + "/" + folder_name + "/twistlock/latest.json"
    anchore = main_dir + "/" + folder_name + "/anchore/anchore_security.json"

    tl_cves = get_twistlock(twistlock)
    oscap_cves = get_oscap(oscap)
    oval_cves = get_oval(oval)
    anchore_cves = get_anchore(anchore)

    total_set = set(tl_cves) | set(oscap_cves) | set(oval_cves) | set(anchore_cves)
    ret = {
        'oscap': oscap_cves,
        'oval': oval_cves,
        'twistlock': tl_cves,
        'anchore': anchore_cves,
        'total': total_set
    }
    return json.dumps(ret, default=set_default)


# works
def download_tarball(url):
    if not os.path.exists(main_dir):
        os.makedirs(main_dir)

    fn = os.path.basename(test_report)
    fpath = main_dir+"/"+fn
    urllib.request.urlretrieve(url, fpath)
    return fpath


# works
def extract_tarball(fpath):
    tar = tarfile.open(fpath)
    fname = os.path.commonprefix(tar.getnames())
    tar.extractall(path=main_dir)
    tar.close()
    return fname


# works
def get_twistlock(twistlock_file):
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

            # print(cve, cvss, desc, exploit, id, link, packageName, packageVersion, severity, status, type, vecStr)
            # print(cve)

            cves.append(cve)
    return cves


# works
def get_oscap(oscap_file):
    with open(oscap_file) as of:
        soup = BeautifulSoup(of, 'html.parser')
        divs = soup.find('div', id="result-details")

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

            cces.append(identifiers)
        return cces


# works
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


# works
def get_anchore(anchore_file):
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
            cves.append(cve)
        return cves


# works
def set_default(obj):
    if isinstance(obj, set):
        return list(obj)
    raise TypeError


if __name__ == "__main__":
    main()  # with if