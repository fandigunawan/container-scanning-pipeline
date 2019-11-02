import csv
import sys
from bs4 import BeautifulSoup
import re
import json
import os
import pandas

def main():
    global csv_dir
    csv_dir = sys.argv[6]
    if not os.path.exists(csv_dir):
        os.mkdir(csv_dir)
    generate_all_reports(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])


# GENERATES ALL OF THE REPORTS FOR ALL OF THE THINGS INCLUDING A SUMMARY INTO /tmp/csvs/
def generate_all_reports(oscap, oval, twistlock, anchore_sec, anchore_gates):
    oscap_fail_count = generate_oscap_report(oscap)
    oval_fail_count = generate_oval_report(oval)
    twist_fail_count = generate_twistlock_report(twistlock)
    anc_sec_count = generate_anchore_sec_report(anchore_sec)
    anc_gate_count = generate_anchore_gates_report(anchore_gates)

    generate_summary_report(oscap_fail_count,
                            oval_fail_count,
                            twist_fail_count,
                            anc_sec_count,
                            anc_gate_count
                            )

    convert_to_excel()

# convert to Excel file
def convert_to_excel():
    read_sum = pandas.read_csv(csv_dir + 'summary.csv')
    read_oscap = pandas.read_csv(csv_dir + 'oscap.csv')
    read_oval = pandas.read_csv(csv_dir + 'oval.csv')
    read_tl = pandas.read_csv(csv_dir + 'tl.csv')
    read_security = pandas.read_csv(csv_dir + 'anchore_security.csv')
    read_gates = pandas.read_csv(csv_dir + 'anchore_gates.csv')
    with pandas.ExcelWriter(csv_dir + 'all_scans.xlsx') as writer:
        read_sum.to_excel(writer, sheet_name='Summary')
        read_oscap.to_excel(writer, sheet_name='OpenSCAP - DISA Compliance')
        read_oval.to_excel(writer, sheet_name='OpenSCAP - OVAL Results')
        read_tl.to_excel(writer, sheet_name='Twistlock Vulnerability Results')
        read_security.to_excel(writer, sheet_name='Anchore CVE Results')
        read_gates.to_excel(writer, sheet_name='Anchore Compliance Results')
    writer.save()

# SUMMARY REPORT
def generate_summary_report(osc, ovf, tlf, asf, agf):
    sum_data = open(csv_dir + 'summary.csv', 'w')
    csv_writer = csv.writer(sum_data)

    csv_writer.writerow(['DRAFT'])
    csv_writer.writerow(['UNCLASSIFIED//FOUO'])

    header = ['Scan', 'Automated Findings', 'Manual Checks', 'Total']
    osl = ['OpenSCAP - DISA Compliance', osc[0], osc[1], osc[0]+osc[1]]
    ovf = ['OpenSCAP - OVAL Results', int(ovf or 0), 0, int(ovf or 0)]
    ancl = ['Anchore CVE Results', int(asf or 0), 0, int(asf or 0)]
    ancc = ['Anchore Compliance Results', int(agf[0] or 0), 0, int(agf[0] or 0)]
    twl = ['Twistlock Vulnerability Results', int(tlf or 0), 0, int(tlf or 0)]

    csv_writer.writerow("")
    csv_writer.writerow(header)
    csv_writer.writerow(osl)
    csv_writer.writerow(ovf)
    csv_writer.writerow(twl)
    csv_writer.writerow(ancl)
    csv_writer.writerow(ancc)
    csv_writer.writerow(['Totals',
                            osl[1]+ovf[1]+ancl[1]+ancc[1]+twl[1],
                            osl[2]+ovf[2]+ancl[2]+ancc[2]+twl[2],
                            osl[3]+ovf[3]+ancl[3]+ancc[3]+twl[3]
                         ])

    csv_writer.writerow("")
    date_str = 'Scans performed on: ' + str(osc[2])
    #csv_writer.writerow(['Scans performed on:', ]) # need date scanned
    sha_str = "Scans performed on container layer sha256:" + agf[1]
    csv_writer.writerow([sha_str])


def generate_oscap_report(oscap):
    oscap_cves = get_oscap_full(oscap)
    oscap_data = open(csv_dir + 'oscap.csv', 'w')
    csv_writer = csv.writer(oscap_data)
    count = 0
    fail_count = 0
    nc_count = 0
    scanned = ""
    for line in oscap_cves:
        if count == 0:
            header = line.keys()
            csv_writer.writerow(header)
            count += 1
        if line['result'] == 'fail':
            fail_count+=1
        elif line['result'] == 'notchecked':
            nc_count+=1
        scanned = line['scanned_date']
        csv_writer.writerow(line.values())
    oscap_data.close()
    return fail_count, nc_count, scanned


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

# OVAL CSV
def generate_oval_report(oval):
    oval_cves = get_oval_full(oval)
    oval_data = open(csv_dir + 'oval.csv', 'w')
    csv_writer = csv.writer(oval_data)
    count = 0
    fail_count = 0
    for line in oval_cves:
        if count == 0:
            header = line.keys()
            csv_writer.writerow(header)
            count += 1
        if line['result'] == 'true':
            fail_count+=1
        csv_writer.writerow(line.values())
    oval_data.close()
    return fail_count


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


# TWISTLOCK CSV
def generate_twistlock_report(twistlock):
    tl_cves = get_twistlock_full(twistlock)
    tl_data = open(csv_dir + 'tl.csv', 'w')
    csv_writer = csv.writer(tl_data)
    count = 0
    for line in tl_cves:
        if count == 0:
            header = line.keys()
            csv_writer.writerow(header)
            count += 1
        csv_writer.writerow(line.values())
    tl_data.close()
    return len(tl_cves)


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


# ANCHORE SECURITY CSV
def generate_anchore_sec_report(anchore_sec):
    anchore_cves = get_anchore_full(anchore_sec)
    anchore_data = open(csv_dir + 'anchore_security.csv', 'w')
    csv_writer = csv.writer(anchore_data)
    count = 0
    for line in anchore_cves:
        if count == 0:
            header = line.keys()
            csv_writer.writerow(header)
            count += 1
        csv_writer.writerow(line.values())
    anchore_data.close()
    return len(anchore_cves)


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

            ret = {
                'tag': tag,
                'cve': cve,
                'severity': severity,
                'vuln': vuln,
                'fix': fix,
                'url': url
            }

            cves.append(ret)
        return cves


# ANCHORE GATES CSV
def generate_anchore_gates_report(anchore_gates):
    anchore_g = get_anchore_gates_full(anchore_gates)
    anchore_data = open(csv_dir + 'anchore_gates.csv', 'w')
    csv_writer = csv.writer(anchore_data)
    count = 0
    stop_count = 0
    for line in anchore_g:
        if count == 0:
            header = line.__dict__.keys()
            csv_writer.writerow(header)
            count+=1
        if line.gate_action == "stop":
            stop_count+=1
        csv_writer.writerow(line.__dict__.values())
        image_id = line.image_id
    anchore_data.close()
    return stop_count, image_id


def get_anchore_gates_full(anchore_file):
    with open(anchore_file) as af:
        json_data = json.load(af)

        top_level = list(json_data)[0]
        anchore_data = json_data[top_level]['result']['rows']
        cves = []
        for x in anchore_data:
            a = AnchoreGate(x)
            cves.append(a)

        # print(json.dumps(anchore_data, indent=4))
        return cves


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


if __name__ == "__main__":
    main()  # with if
