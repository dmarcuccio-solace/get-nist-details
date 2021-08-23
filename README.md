# get-nist-details

Small python script to get CVSSv3 scores from the NIST NVD (National Vulnerability Database) using their [REST API](https://csrc.nist.gov/CSRC/media/Projects/National-Vulnerability-Database/documents/web%20service%20documentation/Automation%20Support%20for%20CVE%20Retrieval.pdf).

Note: requires python3 to run.
<h3>Usage:</h3>

```
getNISTDetails.py [-h] [-c [CVES [CVES ...]]]

  -h, --help            show this help message and exit
  -c [CVES [CVES ...]], --cves [CVES [CVES ...]]
                        List of CVEs to look up. Can be space or comma separated.
```
<h3>Example:</h3>

```
./getNISTDetails.py --cves CVE-2020-0543, CVE-2020-0548, CVE-2020-0549
```

<h5>Output:</h5>

```
CVE-2020-0543 [CVSS v3: 5.5 (MEDIUM)] (https://nvd.nist.gov/vuln/detail/CVE-2020-0543)
CVE-2020-0549 [CVSS v3: 5.5 (MEDIUM)] (https://nvd.nist.gov/vuln/detail/CVE-2020-0549)
CVE-2020-0548 [CVSS v3: 5.5 (MEDIUM)] (https://nvd.nist.gov/vuln/detail/CVE-2020-0548)
```

