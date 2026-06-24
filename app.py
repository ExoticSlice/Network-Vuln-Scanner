from flask import Flask, render_template, jsonify # flask - the web application itself / loads html files and converts python data to json.
from scanner import discover_hosts, scan_services # This imports the two functions you built in scanner.py — discover_hosts to find live hosts and scan_services to enumerate ports and services. The Flask app will use these to run scans when you visit the dashboard.
from cve_lookup import lookup_cves # This imports the lookup_cves function from cve_lookup.py so the Flask app can query the NVD API for CVEs matching the services found.
from risk_engine import calculation_risk # This imports the calculate_risk function so the dashboard can display severity labels for each CVE.

app = Flask(__name__) #This creates the Flask web application object and stores it in app. __name__ tells Flask where to look for templates and static files. Think of it like turning the web server on.

@app.route('/') #This is a route decorator — it tells Flask that when someone visits the homepage (/) of your dashboard, run the function below it. Think of 
def index(): #This is the function that runs when someone visits the homepage. It has no indentation because it's paired with the route decorator above it.
    hosts = discover_hosts('192.168.56.0/24') # This runs the host discovery scan when someone visits the dashboard. It scans the whole subnet and stores the live hosts in a variable called hosts.
    for host in hosts: # loops through each live hosts to scan its service and look up fir cves
        host['service'] = scan_services(host['ip']) # runs the service enumeration scan for each host and stores results directly 
        for service in host['services']: # loops through each service found on the host so we can look up cves for each one.
            service['cves'] = lookup_cves(service['service'], service['version']) 
            for cve in service['cves']: # loops through service found and to calculate the risk level for each one.
                cve['risk'] = calculation_risk(cve['Score']) # calculates teh severity label for ech CVE 
    return render_template('dashboard.html' , hosts=hosts) # sends scan data to an html template an renders it in the browser.

if __name__ == '__main__':
    app.run(debug=True)   # flask auto reloads when chnages are made       
                               

