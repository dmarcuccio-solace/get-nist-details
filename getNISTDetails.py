#!/usr/bin/env python3
import sys
import re
import os
import argparse
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor

parser = argparse.ArgumentParser(description='Gets CVSSv3 scores from NIST given a list of CVEs')
parser.add_argument("-c", "--cves", help="List of CVEs to look up.", nargs='*')
args = parser.parse_args()


def request_session(retries=5, backoff_factor=0.5,status_forcelist=(500, 502, 504),session=None):
    if session == None:
        session = requests.Session()

    retry = Retry(total=retries,read=retries,connect=retries,backoff_factor=backoff_factor,status_forcelist=status_forcelist)
    adapter = HTTPAdapter(max_retries=retry,pool_connections=100,pool_maxsize=100)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session
# END request_session() -------------------------------------

def getCVSSv3Score(cve=None,session=None):
    api_url = "https://services.nvd.nist.gov/rest/json/cve/1.0/" + cve.upper()
    #response = requests.get(api_url)

    try:
        response = request_session(session=session).get(api_url)
    except Exception as x:
        print("Failed to get REST Response for " + cve + ": " + x)
    else:
        base_score = "N/A"
        base_severity = ""
        resp_json = response.json()
        
        if ("result" in resp_json):
            resp_results = resp_json["result"]
            resp_items = resp_results["CVE_Items"]
            resp_impact = resp_items[0]["impact"]
            if ("baseMetricV3" in resp_impact):
                base_score = str(resp_impact["baseMetricV3"]["cvssV3"]["baseScore"])
                base_severity = "(" + resp_impact["baseMetricV3"]["cvssV3"]["baseSeverity"] + ")"
        print(cve + " [CVSS v3: " + base_score + " " + base_severity + "] (https://nvd.nist.gov/vuln/detail/" + cve.upper() + ")")
# END getCVSSv3Score() -------------------------------------

print("")
if args.cves is not None:
    
    # Split up comma-separated CVEs to support lists with both commas and spaces
    cve_list = []
    for cve in args.cves:
        temp_list = cve.split(",")
        for element in temp_list:
            if element != "":
                cve_list.append(element)

    s = requests.Session()

    # Make multithreaded REST calls to get CVSSv3 scores for list of CVEs
    with ThreadPoolExecutor(max_workers=5) as executor:
        for cve in cve_list:
            future = executor.submit(getCVSSv3Score, cve=cve,session=s)
else:
    print("No CVEs given!")