import nmap
import json
def discover_hosts(cidr):
    nm = nmap.PortScanner()
    nm.scan(hosts=cidr, arguments='-sn')
    live_hosts = []
    for host in nm.all_hosts():
        live_hosts.append({
            'ip': host,
            'hostname' : nm[host].hostname(),
            'state' : nm[host].state()
        })
    return live_hosts

if __name__ == '__main__':
    results = discover_hosts('192.168.56.101')
    print (json.dumps(results, indent=2))

