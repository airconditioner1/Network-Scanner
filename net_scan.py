import nmap
nmScanner = nmap.PortScanner()

print("Welcome, this is a nmap automation tool")
print("<------------------------------------------------>")

ip_addr = input("Please enter the IP address you want to scan: ")
print("The IP you entered is: ", ip_addr)

scanType = input(""" \nPlease enter the type of scan you want to run
                    1) SYN ACK Scan
                    2) UDP Scan
                    3) COmprehensive Scan (Description) \n """)
print("You have selected option: ", scanType)

if scanType == '1':
    print("Nmap Version: ", nmScanner.nmap_version())
    nmScanner.scan(ip_addr, '1-1024', '-v -sS')
    print(nmScanner.scaninfo())
    print("Ip Status: ", nmScanner[ip_addr].state())
    print(nmScanner[ip_addr].all_protocols())
    print("Open Ports: ", nmScanner[ip_addr]['tcp'].keys())
elif scanType == '2':
    print("Nmap Version: ", nmScanner.nmap_version())
    nmScanner.scan(ip_addr, '1-1024', '-v -sU')
    print(nmScanner.scaninfo())
    print("Ip Status: ", nmScanner[ip_addr].state())
    print(nmScanner[ip_addr].all_protocols())
    print("Open Ports: ", nmScanner[ip_addr]['udp'].keys())
elif scanType == '3':
    print("Nmap Version: ", nmScanner.nmap_version())
    nmScanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
    print(nmScanner.scaninfo())
    print("Ip Status: ", nmScanner[ip_addr].state())
    print(nmScanner[ip_addr].all_protocols())
    print("Open Ports: ", nmScanner[ip_addr]['tcp'].keys())
else:
    print("Please enter a valid option")