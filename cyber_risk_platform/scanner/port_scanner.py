import nmap
def scan_ports(target):
    nm = nmap.PortScanner()
    nm.scan(target, '1-1024')
    open_ports = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto]:
                if nm[host][proto][port]['state'] == 'open':
                    open_ports.append(port)
    return open_ports
