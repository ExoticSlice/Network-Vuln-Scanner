from reportlab.lib.pagesizes import A4 # imports A4 page size from reportlab library.
from reportlab.lib import colors # color code for severity.
from reportlab.lib.styles import getSampleStyleSheet# import prebuilt text styles from report lab
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle # imports builidng blocks
from datetime import datetime # imports datetime module / use to atuo add todays date to pdf report/ every time report regens, it timestamp it self.

def generate_report(hosts, filename='report.pdf'): # create main func called generate report and takes 2 inputs hosts: scans results containing all hosts,services and CVEs / filename: what to call the pdf file,defaulting to report.pdf if you dont specify one.
    doc = SimpleDocTemplate(filename, pagesize=A4) # creates the pdf docobj stores in doc. takes filename u passed and sets the page size to A4.
    styles = getSampleStyleSheet() # loads pre built text styles into variable called styles. to apply consistent formatting.     
    elements = [] # creates empty list / everything added to pdf gets added to this list first. report lab builds pdf from list in order.
    elements.append(Paragraph("Network Vulnerability Scan Report", styles['Title'])) # adds main titile to pdf like writing a title on a doc
    
