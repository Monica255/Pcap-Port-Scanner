
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
        # print(response_json)
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


# # arspoof - CVE-2019-15022
# arspoof = "CVE-2019-15022"  
# base_score = get_cvss_base_score(arspoof)
# print(f"Base CVSS 3.0 Score for arspoof {arspoof}: {base_score}")

# # bruteforce port 80 -  CVE-2023-33868
# bruteforce = "CVE-2023-33868"  
# base_score = get_cvss_base_score(bruteforce)
# print(f"Base CVSS 3.0 Score for bruteforce p80 {bruteforce}: {base_score}")

# bruteforce port 22 - CVE-2020-1616
# bruteforce22 = "CVE-2020-1616"  
# base_score = get_cvss_base_score(bruteforce22)
# print(f"Base CVSS 3.0 Score for bruteforce p22 {bruteforce22}: {base_score}")

# # ddos - CVE-2023-44487
# ddos = "CVE-2023-44487"  
# base_score = get_cvss_base_score(ddos)
# print(f"Base CVSS 3.0 Score for ddos {ddos}: {base_score}")

# sql injection - CVE-2018-10757
# sql = "CVE-2018-11776"  
# base_score = get_cvss_base_score(sql)
# print(f"Base CVSS 3.0 Score for sql injection {sql}: {base_score}")

