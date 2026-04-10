import nmap # loads pythin-nmap library 
import json # organsing info like a table --- scan results be in a clean readble format
def discover_hosts(cidr): # func discover hosts - resuable code for spefic job. cidr -- network range u scan.
    nm = nmap.PortScanner() # create port scan obj stores in variable nm. everytime to run scan use (nm)
    nm.scan(hosts=cidr, arguments='-sn') # scan happens- nmap ping sweeps network ran u pass in/ -sn check which host alive / dont scan ports yet.
    live_hosts = [] # create empty called live_hosts / like empty container as nmap finds live devices on the network / add each to one into lists
    for hosts in nm.all_hosts(): # loop goes through every live host nmap found one by one. nm.all_hosts() return the list of hosts and each one temo stores in varbale host.
         live_hosts.append({ # { store it as dictionary- which labelled container example. name: vaule.
            'ip': host, # stores ip address of the host in the dictionary. host variable contains the IP thatNmap found.
            'hostname': nm[host].hostname(), # gets the hostname if it has one. ip add 192.18.56.101 / hostname could be metasploitbale. comeup empty if no hostname.
            'state': nm[host].state() # state of the host -it will return up if device alive/responds no comma last item in dictionary.
        })                              
if __name__ == '__main__': # only run code below if file is being run directly/ another file imports the scanner later it wont run auto.
    results = discover_hosts('192.168.56.0/24') # call func u just built passes network range scans & stores all results in varibale called results.
    print(json.dumps(results, indent=2)) # prints scans result clean readable JSON format. 
     