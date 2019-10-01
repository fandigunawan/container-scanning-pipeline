import os
import urllib.request
import tarfile
import json
from bs4 import BeautifulSoup
import re
import pprint
import csv
import helpers

main_dir = "/downloads";
test_report = "https://s3-us-gov-west-1.amazonaws.com/dsop-pipeline-artifacts/container-scan-reports/redhat/ubi7-min/latest/2019-08-20T184227.465_1068/ubi7-min-latest-reports-signature.tar.gz"

def main():
    # result = do_all_the_things(test_report)
    #pp = pprint.PrettyPrinter(indent=4)
    #pp.pprint(result)
    generate_csv_reports(test_report)



def generate_csv_reports(url):
    fp = download_tarball(url)
    folder_name = extract_tarball(fp)
    csv_dir = main_dir + '/' + folder_name + '/csvs'
    os.remove(fp)
    if not os.path.exists(csv_dir):
        os.mkdir(csv_dir)

    oscap = main_dir + "/" + folder_name + "/openscap/report.html"
    oval = main_dir + "/" + folder_name + "/openscap/report-cve.html"
    twistlock = main_dir + "/" + folder_name + "/twistlock/latest.json"
    anchore_sec = main_dir + "/" + folder_name + "/anchore/anchore_security.json"
    anchore_gates = main_dir + "/" + folder_name + "/anchnore/anchore_gates.json"

    # OSCAP CSV
    oscap_cves = get_oscap_full(oscap)
    oscap_data = open(csv_dir + '/oscap.csv', 'w')
    csv_writer = csv.writer(oscap_data)
    count = 0
    for line in oscap_cves:
        if count == 0:
            header = line.keys()
            csv_writer.writerow(header)
            count += 1
        csv_writer.writerow(line.values())
    oscap_data.close()

    # OVAL CSV
    oval_cves = get_oval_full(oval)
    oval_data = open(csv_dir + '/oval.csv', 'w')
    csv_writer = csv.writer(oval_data)
    count = 0
    for line in oval_cves:
        if count == 0:
            header = line.keys()
            csv_writer.writerow(header)
            count += 1
        csv_writer.writerow(line.values())
    oval_data.close()


    # TWISTLOCK CSV
    tl_cves = get_twistlock_full(twistlock)
    tl_data = open(csv_dir + '/tl.csv', 'w')
    csv_writer = csv.writer(tl_data)
    count = 0
    for line in tl_cves:
        if count == 0:
            header = line.keys()
            csv_writer.writerow(header)
            count += 1
        csv_writer.writerow(line.values())
    tl_data.close()

    # ANCHORE SECURITY CSV
    anchore_cves = get_anchore_full(anchore_sec)
    anchore_data = open(csv_dir + '/anchore_security.csv', 'w')
    csv_writer = csv.writer(anchore_data)
    count = 0
    for line in anchore_cves:
        if count == 0:
            header = line.keys()
            csv_writer.writerow(header)
            count += 1
        csv_writer.writerow(line.values())
    anchore_data.close()

    # ANCHORE GATES CSV
    anchore_g = get_anchore_gates_full(anchore_gates)
    anchore_data = open(csv_dir + '/anchore_gates.csv', 'w')
    csv_writer = csv.writer(anchore_data)
    count = 0
    for line in anchore_g:
        if count == 0:
            header = line.keys()
            csv_writer.writerow(header)
            count += 1
        csv_writer.writerow(line.values())
    anchore_data.close()

    # TO DO :: SUMMARY CSV THINGY


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

# done
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


# done
def get_oscap_full(oscap_file):
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
        for x in all:
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


# done
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

# done
def get_oval_full(oval_file):
    oscap = open(oval_file, 'r')
    soup = BeautifulSoup(oscap, 'html.parser')
    results_bad = soup.find_all("tr", class_=["resultbadA", "resultbadB"])
    results_good = soup.find_all("tr", class_=["resultgoodA", "resultgoodB"])

    cves = []
    for x in results_bad + results_good:
        id = x.find("td")
        result = id.find_next_sibling("td")
        cls = result.find_next_sibling("td")
        y = x.find_all(target='_blank')
        references = set()
        for t in y:
            references.add(t.text)
        title = cls.find_next_sibling("td").find_next_sibling("td")

        for ref in references:
            ret = {
                'id': id.text,
                'result': result.text,
                'cls': cls.text,
                'ref': ref,
                'title': title.text
            }
            cves.append(ret)

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

def get_anchore_gates_full(anchore_file):
    with open(anchore_file) as af:
        json_data = json.load(af)

        top_level = list(json_data)[0]
        anchore_data = json_data[top_level]['result']['rows']
        cves = []
        for x in anchore_data:
            a = helpers.AnchoreGate(x)
            cves.append(a)

        # print(json.dumps(anchore_data, indent=4))
        return cves


# works
def set_default(obj):
    if isinstance(obj, set):
        return list(obj)
    raise TypeError


if __name__ == "__main__":
    main()  # with if