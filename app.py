from flask import Flask, render_template, jsonify
from scanner import discover_hosts, scan_services
from cve_lookup import lookup_cves
from risk_engine import calculate_risk

import os
app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), 'templates'))

@app.route('/')
def index():
    hosts = discover_hosts('192.168.56.0/24')
    for host in hosts:
        host['services'] = scan_services(host['ip'])
        for service in host['services']:
            try:
                service['cves'] = lookup_cves(service['services'], service['version'])
            except Exception:
                service['cves'] = []
            for cve in service['cves']:
                cve['risk'] = calculate_risk(cve['score'])
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'unknown': 0}
    for host in hosts:
        for service in host.get('services', []):
            for cve in service.get('cves', []):
                risk = cve['risk'].lower()
                if risk in counts:
                    counts[risk] += 1
    return render_template('dashboard.html', hosts=hosts, counts=counts)

if __name__ == '__main__':
    app.run(debug=True)
