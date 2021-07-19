#!/usr/bin/python3
import json
import os
import sys, yaml, base64, re
from operator import attrgetter
from typing import List

import pdfkit as pdfkit
import requests
from jinja2 import Environment, FileSystemLoader
import cve_searchsploit as CS

def decode_base64_string(base64_string):
    base64_bytes = base64_string.encode('ascii')
    message_bytes = base64.b64decode(base64_bytes)
    return message_bytes.decode('ascii')

def escape_ansi(line):
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', line)

def filter_processes(proc):
    ignore_list = [']', 'grep root', 'ps aux', '-sh', 'init', 'syslogd -n', 'klogd -n']
    for s in ignore_list:
        if proc.endswith(s):
            return False
    return True

class CVE:
    def __init__(self, exploit_name, cve, severity, url, service, service_version):
        self.name = exploit_name
        self.cve = cve
        self.severity = severity
        self.url = url
        self.service = service
        self.service_version = service_version
        self.severity_num = {"UNKNOWN":-1,"LOW":0, "MEDIUM":1, "HIGH":2}[severity]

    def __str__(self):
        return f"{self.cve}: {self.name}. ({self.url}) SEVERITY: {self.severity}"


def get_cve_details(cve_id, exploit_name, service, version) -> CVE:
    # lookup cve details
    cve_info = json.loads(requests.get(f"https://olbat.github.io/nvdcve/{cve_id}.json").text)
    severity = cve_info["impact"]["baseMetricV2"]["severity"]
    url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    return CVE(exploit_name, cve_id, severity, url, service, version)


def lookup_cves(service, version) -> List[CVE]:
    """
    Returns a list of dictionaries that contain the name of a possible exploit, mapped to CVE numbers, by querying searchsploit
    """
    print(f"--> Looking up {service} {version}")
    stream = os.popen(f'searchsploit -o -www {service} {version} | grep -v -E "No Results|----------|Exploit Title"')
    output = stream.read()
    cves = []
    for l in output.splitlines():
        # get name of exploit and corresponding CVE ids
        exploit_name = escape_ansi(l.split('|')[0].strip())
        ex_db_id = l.split('/')[-1].split('.')[0]

        # map exploit-db id to cve
        cve_ids = CS.cve_from_edbid(ex_db_id)
        if cve_ids == []:
            # if cve mapping not possible, crawl exploit-db
            user_agent = "user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.182 Safari/537.36"
            stream =  os.popen(f'curl -H "{user_agent}" https://www.exploit-db.com/exploits/{ex_db_id} 2>/dev/null | grep -Eo "CVE-2[0-9]+-[0-9]+" | head -n 1')
            cve_id = stream.read().strip()
            cve_ids.append(cve_id)

        for cve_id in cve_ids:
            cves.append(get_cve_details(cve_id, exploit_name, service, version))

    return cves


def main():
    print("""┌─┐┬┬─┐┌┬┐┬ ┬┌─┐┬─┐┌─┐  ┌─┐┬ ┬┌─┐┌─┐┬┌─
├┤ │├┬┘││││││├─┤├┬┘├┤   │  ├─┤├┤ │  ├┴┐
└  ┴┴└─┴ ┴└┴┘┴ ┴┴└─└─┘  └─┘┴ ┴└─┘└─┘┴ ┴
""")

    if len(sys.argv) != 2:
        if len(sys.argv) > 2:
            print("Too many arguments!")
        print("Usage: generate_report.py <FC_OUTPUT_YAML_FILE>")
        sys.exit(1)
    input_file = sys.argv[1]
    with open(input_file) as f:
        data = yaml.safe_load(f)

    print("[+] Parsing report data from yaml")
    report_data = data["FirmwareCheck"]
    kernel = report_data['Kernel']
    useful_bins = report_data['Useful_Binaries']
    mysql_pwless_root_allowed = report_data.get('MySQL_pwless-root', False)

    # decode base64 encoded data and parse
    ps_aux = decode_base64_string(report_data['RunningAsRoot'])
    if ps_aux != "":
        root_processes = [p for p in ps_aux.split('\n') if filter_processes(p)]
    else:
        root_processes = []

    netstat = decode_base64_string(report_data['OpenPorts'])
    open_ports = []
    for line in netstat.split('\n'):
        port_number = re.findall(r':[0-9]+', line)
        if port_number:
            port = port_number[-1][1:]
            if port not in open_ports:
                open_ports.append(port)

    serial_ports = decode_base64_string(report_data['SerialPorts']).split('\n')

    # parse services and versions from sh space separated list
    service_versions = {}
    services = report_data['Services'].split(" ")
    versions = report_data['Versions'].split(" ")
    for i in range(0, len(services)):
        service_versions[services[i]] = versions[i]

    print("[+] Looking up CVEs")
    cves = []
    #service cves
    for service, version in service_versions.items():
        cves += lookup_cves(service, version)

    # kernel exploits
    stream = os.popen(f"linux-exploit-suggester -k {kernel} | grep '[+]'")
    kernel_exploits = []
    for exploit in stream.read().splitlines():
        exploit = escape_ansi(exploit)
        cve_id = exploit.split('[')[2].split(']')[0]
        exploit_name = exploit.split(']')[2]
        kernel_exploits.append(get_cve_details(cve_id, exploit_name, "Linux Kernel", kernel))
    cves += kernel_exploits

    # count and sort for piechart and list in report
    cve_data = {"UNKNOWN":0, "LOW":0, "MEDIUM":0, "HIGH":0}
    cves = sorted(cves, key=attrgetter('severity_num'), reverse=True)
    for cve in cves:
        cve_data[cve.severity] = cve_data.get(cve.severity, 0) + 1
    piechart_data = list(cve_data.values())

    # generate report
    templateLoader = FileSystemLoader(searchpath="./")
    templateEnv = Environment(loader=templateLoader)
    report_template = templateEnv.get_template("report_template.html")
    report = report_template.render(
        kernel=kernel,
        useful_bins=useful_bins,
        open_ports=open_ports,
        root_processes=root_processes,
        serial_ports=serial_ports,
        service_versions=service_versions,
        cves=cves,
        piechart_data=piechart_data,
        mysql_pwless_root_allowed=mysql_pwless_root_allowed,
        piechart_labels=["Unknown", "Low", "Medium", "High"]
    )

    with open("report.html", "w") as f:
        f.write(report)

    pdfkit.from_file(
        "report.html",
        "report.pdf",
        options={
            'quiet': ''
        }
    )
    print("[+] Report saved to report.html and report.pdf")

if __name__ == "__main__":
    main()