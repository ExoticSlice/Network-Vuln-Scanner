from reportlab.lib.pagesizes import A4 # imports A4 page size from reportlab library.
from reportlab.lib import colors # color code for severity.
from reportlab.lib.styles import getSampleStyleSheet# import prebuilt text styles from report lab
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle # imports builidng blocks
from datetime import datetime # imports datetime module / use to atuo add todays date to pdf report/ every time report regens, it timestamp it self.
from risk_engine import calculate_risk
def generate_report(hosts, filename='report.pdf'): # create main func called generate report and takes 2 inputs hosts: scans results containing all hosts,services and CVEs / filename: what to call the pdf file,defaulting to report.pdf if you dont specify one.
    doc = SimpleDocTemplate(filename, pagesize=A4) # creates the pdf docobj stores in doc. takes filename u passed and sets the page size to A4.
    styles = getSampleStyleSheet() # loads pre built text styles into variable called styles. to apply consistent formatting.     
    elements = [] # creates empty list / everything added to pdf gets added to this list first. report lab builds pdf from list in order.
    elements.append(Paragraph("Network Vulnerability Scan Report", styles['Title'])) # adds main titile to pdf like writing a title on a doc
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%D/%m/%Y %H:%M')}", styles['Normal'])) # gets current date and time and format to uk style
    elements.append(Spacer(1, 20)) # adds blank space of 20 units ater the title and date. makes room baically.  ELEMENTS APPEND HOW WE ADD THINGS TO PDF.
    elements.append(Paragraph("Executive Summary", styles['Heading1'])) # adds first section heading 
    total_hosts = len(hosts) # counts total number of hosts that were scanned and stores it.  if 3 scanned 3 hosts 3 returns.
    elements.append(Paragraph(f"Total Hosts scanned:{total_hosts}", styles['Normal'])) # adds line to pdf showign how many hosts were scanned. the "f" inserts tota; hosts number in to the text.
    elements.append(Spacer(1,20)) # adds another blank space after exceutive summary section before the next section starts.
    elements.append(Paragraph("findings", styles['Heading1'])) #  where vulnerability details will be listed by host.
    for host in hosts: # loops through each host that was scanned and for each host we'll add its ip address, services and CVE's report.
        elements.append(Paragraph(f"Host: {host['ip']}", styles['Heading2'])) # adds hosts IP address subheading for each host section in report.
        for service in host.get('services', []): # loops through all services found on the host. get's services list from this host and if not any then use empty list.
            elements.append(Paragraph(f"Port {service['port']} - {service['service']} {service['version']}", styles['Normal'])) # adds a line each service showing the port number, service name and version -- for example port 22 -ssh openssh4.7. core finding information that maps directly to CVE's
            for cve in service.get('cves', []): # loops through cves found for that service. if no cve's found it just uses a empty list.
                risk = calculate_risk(cve['score']) # calls your risk calculate function from risk engine py to get severity label for each cve. 9.5 is critical and 7.2 is high
                elements.append(Paragraph(f"[{risk}] {cve['cve_id']} - Score: {cve['score']}", styles['Normal'])) 
                elements.append(Paragraph(f"Description: {cve['description']}", styles['Normal'])) # this add description for each CVE ID.
                elements.append(Spacer(1, 10)) # so that it is not crammed.   
    elements.append(Spacer(1, 20)) # adds larger space after findings seperates findings section to section.
    elements.append(Paragraph("Remediation Summary", styles['Heading1'])) # this section is where you list things that need to be fixed
    Table_data = [['CVE ID', 'Severity', 'Score', 'Recommendation']] # creates headder for the table and is a list inside a list like a spreadsheet
    for host in hosts: # loops through all hosts to gather CVE data for the table.
        for service in host.get('service', []):
            for cve in service.get('cves', []):
                risk = calculate_risk(cve['score']) # get severity label for each cve same as before.
                Table_data.append([cve['cve_id'], risk, str(cve['score']), 'Update or patch affected service']) # adds a row to the remedoation table for each cve with four coloums
    table = Table(table_data)     # creates actual table object from all the data You've built up Reportlab takes your list and turns to a formatted table ready to add to pdf. 
    Table.setStyle(TableStyle([  # start applying styles to our table.
        ('BACKGROUND', (0,0), (-1,0), color.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('GRID', (0,0), (-1, -1), 1, colors.black),
    ])) # closes the style rules.
    elements.append(Table) # adds completed styled table
    doc.build(elements)

if __name__ == '__main__':
    test_data = [{
        'ip': '192.168.56.101',
        'services': [{
            'port': 22,
            'service': 'ssh',
            'version': 'OpenSSH 4.7',
            'cves': [{
                'cve_id': 'CVE-2007-4752',
                'description': 'Test vulnerability',
                'score': 7.5
            }]
        }]
    }]
    generate_report(test_data, 'test_report.pdf')
    print("Report generated successfully!")