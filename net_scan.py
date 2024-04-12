import nmap
nmScanner = nmap.PortScanner()

print("Welcome, this is a nmap automation tool")
print("<------------------------------------------------>")

ip_addr = input("Please enter the IP address you want to scan: ")
print("The IP you entered is: ", ip_addr)

scanType = input(""" \nPlease enter the type of scan you want to run
                    1) SYN ACK Scan
                    2) UDP Scan
                    3) COmprehensive Scan (Description) """)
print("You have selected option: ", scanType)
# nmScanner.scan('10.0.0.1', '21-443')

# for host in nmScanner.all_hosts():
#     print(host)