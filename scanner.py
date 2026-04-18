import nmap # loads python-nmap library 
import json # organsing info like a table --- scan results be in a clean readble format
def discover_hosts(cidr): # func discover hosts - resuable code for spefic job. cidr -- network range u scan.
    nm = nmap.PortScanner() # create port scan obj stores in variable nm. everytime to run scan use (nm)
    nm.scan(hosts=cidr, arguments='-sn') # scan happens- nmap ping sweeps network ran u pass in/ -sn check which host alive / dont scan ports yet.
    live_hosts = [] # create empty called live_hosts / like empty container as nmap finds live devices on the network / add each to one into lists
    for host in nm.all_hosts(): # loop goes through every live host nmap found one by one. nm.all_hosts() return the list of hosts and each one temo stores in varbale host.
         live_hosts.append({ # { store it as dictionary- which labelled container example. name: vaule.
            'ip': host, # stores ip address of the host in the dictionary. host variable contains the IP thatNmap found.
            'hostname': nm[host].hostname(), # gets the hostname if it has one. ip add 192.18.56.101 / hostname could be metasploitbale. comeup empty if no hostname.
            'state': nm[host].state() # state of the host -it will return up if device alive/responds no comma last item in dictionary.
        })
def scan_services(host):
    nm = nmap.PortScanner()
    nm.scan(hosts=host, arguments='-sV -sC -T4')
    services = []
    for port in nm[host].all_tcp():
        service = nm[host]['tcp'][port]
        services.append({
            'port': port,        
            'state': service['state'],
            'services': service['name'],
            'version': service['version'],          
        }) 
    return services

if __name__ == '__main__': # only run code below if file is being run directly/ another file imports the scanner later it wont run auto.
    hosts = discover_hosts('192.168.56.101') # call func u just built passes network range scans & stores all results in varibale called results.
    print("live hosts:", json.dumps(results, indent=2)) # prints scans result clean readable JSON format. 
    for h in hosts:
        print(f"\nscanning services on {h['ip']}...") 
        services = scan_services(h['ip'])
        print(json.dumps(services,indent=2))
     