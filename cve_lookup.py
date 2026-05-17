import requests # lets python make web requests. NVD API to Fetch CVE Data
import time # adds a small delay between API requests so NVD rate Limit is not met
import json 

def lookup_cves(service, version): # takes two inputs , service and name like ssh or http or 4.7 or 2.2.8 use either to search NVD API for matching vulnerabilites.  
    query = f"{service}  {version}" #combines service name and version into one string. f string lets you insert variables directly into string. like ssh service and version 4.7 the query is 4.7.
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}"# builds full url for NVD API request. takes query and adds to the end of NVD API addresses. when code sends request this URL the NVD database will search for CVEs matches ur service / version.
    response = requests.get(url) # request to NVD API stores the response in varible called response.
    time.sleep(1) #pauses code 1 second after each API request. to fast request will get blocked.
    if response.status_code != 200: # checks if API request was successful 200 is the http status code for success- like a green light. anything other than 200 it means soemthign went wrong like API is down or you been rate limited. 
        return [] # returns an empty list if request is failed so rest of the code does not crash trying to process a bad response
    data = response.json() # converts API response from raw text into python dictionary that u can work with JSON is the format the NVD API returns data in that python can read.
    cves = [] # create empty list and as we pull CVE data out of the API Response we add to the list.
    for item in data.get('vulnerabilities', []): # this loops through vulns the NVD API returned means get the vulns list from the data if there arent any just use a empty list.
        cve = item['cve'] # gets cve data from each item in the lopp and stores it in variable called cve. each item contains detailed info about one specific vuln
        cve_id = cve['id'] # get CVE ID unique identifier each vuln e.g. CVE-2001-28041. This is what you'll see on security advisories and vulnerabiity databases.   
        description = cve['descriptions'][0]['value']# gets description of vulnerability / explanation of what cve is and whats affects.
        try: # try to run the code inside, and if something goes wrong dont crash CVE has a CVSS score if we try to access one that doesnt exist python would throw an error.
            score = cve['metrics']['cvssMetricV31'][0]['cvssData']['baseScore'] # cvss score of the vulnerability -a number between 0 and 10 that tells you how sever it is. the higher number the more danagerous the vulnerability. for example 9.8 is ciritical 4.5 is meduim. 
        except (KeyError, IndexError): # This catches any errors that happen if the CVSS score doesnt exist in the data key error means a dictionary key wasnt found
            score = None # sets score to non if cvss score doesnt exist in data.
        cves.append({ # new items to our cves list for each vulnerability found. { means we storing it as a dictionary with labelled info.
            'cve_id': cve_id, # stores cve id in the dictionary - e.g. cve-2021-28041. this is the unique identifier you'll display in your report.
            'description': description, # stores plain english description of vulnerability
            'score': score # stores CVSS score in dictionary. no comma due to last item in the dictionary.
        }) # closes thr dictionaryand the append from line 21
    return cves # sends completed lsit of CVE back to whoever called the fuction - same pattern as return live_hosts and return services in scanner.py
if __name__ == '__main__':
    results = lookup_cves('ssh', 'OpenSSH 4.7')
    print(json.dumps(results, indent=2))
