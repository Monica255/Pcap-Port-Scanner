
import requests
from cvss import CVSS3 
import re

class Constants:
    PATCH = "Patch"
    VENDOR_ADVISORY= "Vendor Advisory"
    THIRD_PARTY_ADVISORY= "Third Party Advisory"
    EXPLOIT= "Exploit"

def is_valid_cve(cve):
  pattern = r"CVE-\d{4}-\d{4}"
  return bool(re.match(pattern, cve))

import requests

def get_cvss_base_score(cve_id):
    auth = None
    headers = {'Accept': 'application/json'}
    
    try:
        response = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}", auth=auth, headers=headers)
        
        if response.status_code != 200:
            return -1
        
        response_json = response.json()
        vulnerabilities = response_json.get('vulnerabilities', [])
        
        if not vulnerabilities:
            return -1
        
        cvss3_base_score = None
        
        if 'cvssMetricV31' in vulnerabilities[0]['cve']['metrics']:
            cvss3_base_score = vulnerabilities[0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
        elif 'cvssMetricV30' in vulnerabilities[0]['cve']['metrics']:
            cvss3_base_score = vulnerabilities[0]['cve']['metrics']['cvssMetricV30'][0]['cvssData']['baseScore']
        
        if cvss3_base_score is None:
            return -1
        
        return float(cvss3_base_score)
    
    except requests.exceptions.RequestException:
        return -1 
    except Exception as e:
        return -1  

# cve_id = "CVE-2016-0777"  
# base_score = get_cvss_base_score(cve_id)
# print(f"Base CVSS 3.0 Score for {cve_id}: {base_score}")
