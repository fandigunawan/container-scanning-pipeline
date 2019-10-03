import report_helpers
import csv
import json

debug = 0

path_to_oscap_file = ""
path_to_oval_file = ""
path_to_twistlock_file = ""
path_to_anchore_sec_file = ""
path_to_anchore_gates_file = ""


def main():
    generate_all_reports(
        path_to_oscap_file,
        path_to_oval_file,
        path_to_twistlock_file,
        path_to_anchore_sec_file,
        path_to_anchore_gates_file,
        path_for_output
    )

csv_dir = path_for_output


def generate_all_reports(oscap, oval, twistlock, anchore_sec, anchore_gates):
    oscap_fail_count = generate_oscap_report(oscap)
    oval_fail_count = generate_oval_report(oval)
    twist_fail_count = generate_twistlock_report(twistlock)
    anc_sec_count = generate_anchore_sec_report(anchore_sec)
    anc_gate_count = generate_anchore_gates_report(anchore_gates)

    generate_summary_report(oscap_fail_count[0],
                            oscap_fail_count[1],
                            oval_fail_count,
                            twist_fail_count,
                            anc_sec_count,
                            anc_gate_count
                            )
    if debug:
        print("OSCAP FAILS: " + str(oscap_fail_count[0]))
        print("OSCAP NOT CHECKED: " + str(oscap_fail_count[1]))
        print("OVAL FAILS: " + str(oval_fail_count))
        print("TWISTLOCK FAILS: " + str(twist_fail_count))
        print("ANCHORE SEC FAILS: " + str(anc_sec_count))
        print("ANCHORE GATE FAILS: " + str(anc_gate_count))


# SUMMARY REPORT
def generate_summary_report(of, onc, ovf, tlf, asf, agf):
    sum_data = open(csv_dir + '/summary.csv', 'w')
    csv_writer = csv.writer(sum_data)

    csv_writer.writerow(['DRAFT'])
    csv_writer.writerow(['UNCLASSIFIED//FOUO'])

    header = ['Scan', 'Automated Findings', 'Manual Checks', 'Total']
    osl = ['OpenSCAP - DISA Compliance', of, onc, of+onc]
    ovf = ['OpenSCAP - OVAL Results', int(ovf or 0), 0, int(ovf or 0)]
    ancl = ['Anchore CVE Results', int(asf or 0), 0, int(asf or 0)]
    ancc = ['Anchore Compliance Results', int(agf or 0), 0, int(agf or 0)]
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
    csv_writer.writerow(['Notes'])
    csv_writer.writerow(['Anchore Results are based on an older version of CVSS, and will be supporting the newer (CVSS 3.0) in a future release'])

    csv_writer.writerow("")
    csv_writer.writerow(['Scans performed', ]) # need date scanned
    csv_writer.writerow(['On container layer sha256:', ]) # need container sha



# OSCAP CSV
def generate_oscap_report(oscap):
    oscap_cves = report_helpers.get_oscap_full(oscap)
    oscap_data = open(csv_dir + '/oscap.csv', 'w')
    csv_writer = csv.writer(oscap_data)
    count = 0
    fail_count = 0
    nc_count = 0
    for line in oscap_cves:
        if count == 0:
            header = line.keys()
            csv_writer.writerow(header)
            count += 1
        if line['result'] == 'fail':
            fail_count+=1
        elif line['result'] == 'notchecked':
            nc_count+=1
        csv_writer.writerow(line.values())
    oscap_data.close()
    return fail_count, nc_count


# OVAL CSV
def generate_oval_report(oval):
    oval_cves = report_helpers.get_oval_full(oval)
    oval_data = open(csv_dir + '/oval.csv', 'w')
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


# TWISTLOCK CSV
def generate_twistlock_report(twistlock):
    tl_cves = report_helpers.get_twistlock_full(twistlock)
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
    return len(tl_cves)


# ANCHORE SECURITY CSV
def generate_anchore_sec_report(anchore_sec):
    anchore_cves = report_helpers.get_anchore_full(anchore_sec)
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
def generate_anchore_gates_report(anchore_gates):
    anchore_g = report_helpers.get_anchore_gates_full(anchore_gates)
    anchore_data = open(csv_dir + '/anchore_gates.csv', 'w')
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
    anchore_data.close()
    return stop_count


if __name__ == "__main__":
    main()  # with if
