from netmiko import ConnectHandler
from nornir import InitNornir
from nornir_utils.plugins.functions import print_result
from nornir.core.filter import F
from getpass import getpass
import logging


def test_connection(host):
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((host, 23))  
        s.close()
        return True
    except Exception as e:
        print(f"\033[91mCannot connect to device {host} : {e} \033[0m")
        return False 
    
def send_command(task, command):
    device_name = task.host.name
    password = passwords.get(device_name)
    if password is None:  
        if not test_connection(task.host.hostname):
            logging.error(f"\033[91m Cannot connect to {device_name} \033[0m")  
            return "Cannot connect to device"
        password = getpass("Enter the password for device \033[92m{}\033[0m: ".format(device_name))
        passwords[device_name] = password

    device_type = task.host.get('device_type', 'cisco_ios_telnet')
    
    try:
        net_connect = ConnectHandler(device_type=device_type, ip=task.host.hostname, username=task.host.username, password=password)
        result = net_connect.send_command_timing("enable")  
        if "Password:" in result:  
            result += net_connect.send_command_timing(password)  
        result += net_connect.send_command_timing(command)  
    except Exception as e:
        logging.error(f"\033[91m {str(e)} \033[0m")  
        result = str(e)
    finally:
        if net_connect:
            net_connect.disconnect()

    return result

def filter_group(nr, group_name):
    
    filtered_nr = nr.filter(F(groups__contains=group_name))
    hosts = filtered_nr.inventory.hosts
    num_hosts = len(hosts)
    
    if num_hosts > 0:
        print(f"Number of hosts after filtering: {num_hosts}")
        print("Devices in group \033[33m{}\033[0m:".format(group_name))
        return filtered_nr, hosts
    else:
        print("No devices found in group \033[33m{}\033[0m.".format(group_name))
        return None, None
    
def show_acl(filtered_nr):
    show_acl ="enable\n"
    show_acl += f"show access-list"
    
    result = filtered_nr.run(task=send_command, command=show_acl)
    print_result(result)
    filtered_nr.close_connections()
    
def delete_on_interface (filtered_nr):
    delete_on_interface = "enable\n"
    interface = input("Enter interface : ")
    delete_on_interface += f"int {interface}"
    delete_on_interface += f"show ip access-group"
    acl_name = input("Enter ACL name : ")
     
    flow = input("Select direction of pecket flow (in / out): ")
    delete_on_interface += f"no ip access-group {acl_name} {flow}"
    
    result = filtered_nr.run(task=send_command, command=delete_on_interface)
    print_result(result)
    filtered_nr.close_connections()
    
    
def delete_some_line (filtered_nr):
    delete_some_line = "enable\n"
    acl_name = input("Enter ACL name : ")
    delete_some_line += f"show access {acl_name}"
    line_number = input("Enter line number to delete : ")
    delete_some_line += f"no {line_number}"
    delete_some_line += f"show access {acl_name}"
    
    
    
    result = filtered_nr.run(task=send_command, command=delete_some_line)
    print_result(result)
    filtered_nr.close_connections()
    
def delete_acl(filtered_nr):
    acl_name = input("Enter ACL name : ")
    delete_acl += f"no access-list {acl_name}"
    
    result = filtered_nr.run(task=send_command, command=delete_acl)
    print_result(result)
    filtered_nr.close_connections()
    
def main_delete_acl(filtered_nr):
    print("1.Delete on interface\n 2.Delete some line\n 3.Delete ACL \n")
    user_action = input("Choose action : ")
    
    if user_action == "1":
        delete_on_interface (filtered_nr)
        
    elif user_action == "2":
        delete_some_line (filtered_nr)
        apply_acl(filtered_nr)
        
    elif user_action == "3":
        delete_acl(filtered_nr)
    
def apply_acl (filtered_nr, password):
    
    flow = input("Select direction of pecket flow (in / out): ")
    if flow == "in":
        inbound(filtered_nr, password)
    elif flow == "out":
        outbound(filtered_nr, password)  
    
def basic_acl (filtered_nr, password):
    
    print("top 10 access control list for network")
    print("1 Block a Specific IP Address")
    print("2 Allow SSH from a Specific IP Address")
    print("3 Deny All Telnet Traffic")
    print("4 Allow Web Traffic HTTP from a Subnet")
    print("5 Allow Web Traffic HTTPS from a Subnet")
    print("6 Block All Traffic from a Specific Subnet")
    print("7 Allow ICMP for Ping")
    print("8 Deny All Traffic to a Sensitive Server")
    print("9 Allow DNS Queries")
    print("10 Allow DHCP Responses")
    print("11 Exit")
    user_action = input("Choose action : ")
    
    if user_action == "1":
        Block_a_specific_IP_address(filtered_nr) 
        apply_acl (filtered_nr)
        
    elif user_action == "2":
        Allow_SSH_from_a_specific_IP_Address(filtered_nr)
        apply_acl (filtered_nr)
        
    elif user_action == "3":
        Deny_all_telnet_traffic(filtered_nr)
        apply_acl (filtered_nr)
        
    elif user_action == "4":
        Allow_web_traffic_HTTP_from_a_Subnet(filtered_nr)     
        apply_acl (filtered_nr)
        
    elif user_action == "5":
        Allow_Web_Traffic_HTTPS_from_a_Subnet (filtered_nr)
        apply_acl (filtered_nr)  
         
    elif user_action == "6":
        Block_All_Traffic_from_a_Specific_Subnet (filtered_nr) 
        apply_acl (filtered_nr)
            
    elif user_action == "7":
        Allow_ICMP_for_Ping (filtered_nr)
        apply_acl (filtered_nr)
            
    elif user_action == "8":
        Deny_All_Traffic_to_a_Sensitive_Server (filtered_nr)
        apply_acl (filtered_nr)
        
    elif user_action == "9":
        Allow_DNS_Queries (filtered_nr)
        apply_acl (filtered_nr)
        
    elif user_action == "10":
        Allow_DHCP_Responses(filtered_nr)
        apply_acl (filtered_nr)
    
    elif user_action == "11":
        print("Exiting Basic ACL ...")
        return
        
    else:
        print("Invalid selection. Please try again.")
    
    
def Block_a_specific_IP_address(filtered_nr):
    
    acl_name = input("Enter ACL name : ")
    Block_a_specific_IP_address = f"enable\nconf t\n"
    Block_a_specific_IP_address += f"ip access-list extended {acl_name}\n"
    
    ip = input("Enter IP adress ")
    Block_a_specific_IP_address += f"deny ip host {ip} any\n"
    
    result = filtered_nr.run(task=send_command, command=Block_a_specific_IP_address)
    print_result(result)
    filtered_nr.close_connections()
    
def Allow_SSH_from_a_specific_IP_Address(filtered_nr): 
    
    acl_name = input("Enter ACL name : ")
    Allow_SSH_from_a_specific_IP_Address = f"enable\nconf t\n"
    Allow_SSH_from_a_specific_IP_Address += f"ip access-list extended {acl_name}\n"
    
    ip = input("Enter IP adress ")
    basic_acl += f"permit tcp host {ip} any eq 22\n"  
    
    result = filtered_nr.run(task=send_command, command=Allow_SSH_from_a_specific_IP_Address)
    print_result(result)
    filtered_nr.close_connections()

def Deny_all_telnet_traffic(filtered_nr):     
    
    acl_name = input("Enter ACL name : ")
    Deny_all_telnet_traffic = f"enable\nconf t\n"
    Deny_all_telnet_traffic += f"ip access-list extended {acl_name}\n"
    
    Deny_all_telnet_traffic += f"deny tcp any any eq 23\n"
    
    result = filtered_nr.run(task=send_command, command=Deny_all_telnet_traffic)
    print_result(result)
    filtered_nr.close_connections()

def Allow_web_traffic_HTTP_from_a_Subnet(filtered_nr):      
    
    acl_name = input("Enter ACL name : ")
    Allow_web_traffic_HTTP_from_a_Subnet = f"enable\nconf t\n"
    Allow_web_traffic_HTTP_from_a_Subnet += f"ip access-list extended {acl_name}\n"
    
    ip = input("Enter  IP adress: ")
    wildcard_masks =input("Enter wildcard masks: ")
    Allow_web_traffic_HTTP_from_a_Subnet += f"permit tcp {ip} {wildcard_masks} any eq 80\n"
        
    result = filtered_nr.run(task=send_command, command=Allow_web_traffic_HTTP_from_a_Subnet)
    print_result(result)
    filtered_nr.close_connections()
  
def Allow_Web_Traffic_HTTPS_from_a_Subnet (filtered_nr): 
    
    acl_name = input("Enter ACL name : ")
    Allow_Web_Traffic_HTTPS_from_a_Subnet = f"enable\nconf t\n"
    Allow_Web_Traffic_HTTPS_from_a_Subnet += f"ip access-list extended {acl_name}\n"
    
    ip = input("Enter  IP adress: ")
    wildcard_masks =input("Enter wildcard masks: ")
    Allow_Web_Traffic_HTTPS_from_a_Subnet += f"permit tcp {ip} {wildcard_masks} any eq 443\n"
    
    result = filtered_nr.run(task=send_command, command=Allow_Web_Traffic_HTTPS_from_a_Subnet)
    print_result(result)
    filtered_nr.close_connections()
    
def Block_All_Traffic_from_a_Specific_Subnet (filtered_nr): 
    
    acl_name = input("Enter ACL name : ")
    Block_All_Traffic_from_a_Specific_Subnet = f"enable\nconf t\n"
    Block_All_Traffic_from_a_Specific_Subnet += f"ip access-list extended {acl_name}\n"
    
    ip = input("Enter  IP adress: ")
    wildcard_masks =input("Enter wildcard masks: ")
    Block_All_Traffic_from_a_Specific_Subnet += f"permit ip {ip} {wildcard_masks} any\n"
    
    result = filtered_nr.run(task=send_command, command=Block_All_Traffic_from_a_Specific_Subnet)
    print_result(result)
    filtered_nr.close_connections()

def Allow_ICMP_for_Ping (filtered_nr): 
     
    acl_name = input("Enter ACL name : ")
    Allow_ICMP_for_Ping = f"enable\nconf t\n"
    Allow_ICMP_for_Ping += f"ip access-list extended {acl_name}\n"
    
    Allow_ICMP_for_Ping += f"permit icmp any any echo\n"
    Allow_ICMP_for_Ping += f"permit icmp any any echo-reply\n"
    
    result = filtered_nr.run(task=send_command, command=Allow_ICMP_for_Ping)
    print_result(result)
    filtered_nr.close_connections()

def Deny_All_Traffic_to_a_Sensitive_Server (filtered_nr):  
        
    acl_name = input("Enter ACL name : ")
    Deny_All_Traffic_to_a_Sensitive_Server = f"enable\nconf t\n"
    Deny_All_Traffic_to_a_Sensitive_Server += f"ip access-list extended {acl_name}\n"
    
    ip = input("Enter sensitive IP adress: ")
    Deny_All_Traffic_to_a_Sensitive_Server += f"deny ip any host {ip}\n"
        
    result = filtered_nr.run(task=send_command, command=Deny_All_Traffic_to_a_Sensitive_Server)
    print_result(result)
    filtered_nr.close_connections()

def Allow_DNS_Queries (filtered_nr):
    
    acl_name = input("Enter ACL name : ")
    Allow_DNS_Queries = f"enable\nconf t\n"
    Allow_DNS_Queries += f"ip access-list extended {acl_name}\n"
    
    Allow_DNS_Queries += f"permit udp any any eq 53\n"
     
    result = filtered_nr.run(task=send_command, command=Allow_DNS_Queries)
    print_result(result)
    filtered_nr.close_connections()

def Allow_DHCP_Responses(filtered_nr):
    
    acl_name = input("Enter ACL name : ")
    Allow_DHCP_Responses = f"enable\nconf t\n"
    Allow_DHCP_Responses += f"ip access-list extended {acl_name}\n"
    
    Allow_DHCP_Responses += f"permit udp any eq 67 any eq 68\n"  # 67 DHCP Server ,68 DHCP Client
    
    result = filtered_nr.run(task=send_command, command=Allow_DHCP_Responses)
    print_result(result)
    filtered_nr.close_connections()

    
def advdance_acl(filtered_nr, password):
    acl_name = input("Enter ACL name : ")
    
    basic_acl = f"enable\nconf t\n"
    basic_acl += f"ip access-list extended {acl_name}\n"
    
    print("advdance access control list for network")
    print("1 Deny ICMP")
    print("2 Deny domain name")
    print("3 Deny TCP")
    print("4 Deny UDP")
    print("5 Deny IP")
    print("6 Permit ICMP")
    print("7 Permit domain name")
    print("8 Permit TCP")
    print("9 Permit UDP")
    print("10 Permit IP")
    print("11 Exit")
    
    user_action = input("Choose action : ")
        
    if user_action == "1":
        deny_icmp(filtered_nr, password)
        apply_acl (filtered_nr)
            
    elif user_action == "2":
        deny_domainname(filtered_nr, password) 
        apply_acl (filtered_nr)
        
    elif user_action == "3":
        deny_tcp(filtered_nr, password) 
        apply_acl (filtered_nr)
        
    elif user_action == "4":
        deny_udp(filtered_nr, password) 
        apply_acl (filtered_nr)
            
    elif user_action == "5":
        deny_ip(filtered_nr, password) 
        apply_acl (filtered_nr)
        
    elif user_action == "6":
        permit_icmp(filtered_nr, password) 
        apply_acl (filtered_nr)
            
    elif user_action == "7":
        permit_domainname(filtered_nr, password) 
        apply_acl (filtered_nr)
        
    elif user_action == "8":
        permit_tcp(filtered_nr, password) 
        apply_acl (filtered_nr)
            
    elif user_action == "9":
        permit_udp(filtered_nr, password) 
        apply_acl (filtered_nr)
        
    elif user_action == "10":
        permit_ip(filtered_nr, password) 
        apply_acl (filtered_nr)
        
    elif user_action == "11":
        print("Exiting program...")
        exit
        
    else:
        print("Invalid selection. Please try again.")
        
def deny_icmp(filtered_nr, password):
    acl_name = input("Enter ACL name : ")
    print("Would you like to spacific \n 1.Source\n 2.Destination\n 3.Source and Destination\n 4.Range\n 5.Not specific\n 6.Exit\n ")
    user_action = input("Choose action : ")
    
    deny_icmp = f"enable\n{password}\nconf t\n"
    deny_icmp += f"ip access-list extended {acl_name}\n"
    
    if user_action == "1":
        deny_icmp_source = input("Enter source IP adress ")
        deny_icmp += f"deny icmp host {deny_icmp_source} any\n"
        
    elif user_action == "2":
        deny_icmp_dest = input("Enter destination IP adress ")
        deny_icmp  += f"deny icmp any host {deny_icmp_dest}\n"  
        
    elif user_action == "3":
        deny_icmp_source = input("Enter source IP adress ")
        deny_icmp_dest  = input("Enter Destination IP adress ")
        deny_icmp += f"deny icmp host {deny_icmp_source} host {deny_icmp_dest}\n"
        
    elif user_action == "4":
        source_ip = input("Enter source IP adress: ")
        source_wildcard_masks =input("Enter source wildcard masks: ")
        destination_ip = input("Enter destination ip: ")
        destination_wildcard_masks =input("Enter destination wildcard masks: ")
        deny_icmp += f"deny icmp {source_ip} {source_wildcard_masks} {destination_ip} {destination_wildcard_masks}\n"              
        
    elif user_action == "5":     
        deny_icmp += f"deny icmp any any\n"
        
    elif user_action == "6":
        print("Exiting function...")
        exit
        
    else:
        print("Invalid selection. Please try again.")
             
    result = filtered_nr.run(task=send_command, command=deny_icmp)
    print_result(result)
    filtered_nr.close_connections()


def permit_icmp(filtered_nr, password):
    acl_name = input("Enter ACL name : ")
    print("Would you like to spacific \n 1.Source\n 2.Destination\n 3.Source and Destination\n 4.Range\n 5.Not specific\n 6.Exit\n ")
    user_action = input("Choose action : ")
    
    permit_icmp = f"enable\n{password}\nconf t\n"
    permit_icmp += f"ip access-list extended {acl_name}\n"
    
    if user_action == "1":
        permit_icmp_source = input("Enter source IP adress ")
        permit_icmp += f"permit icmp host {permit_icmp_source} any\n"
        
    elif user_action == "2":
        permit_icmp_dest = input("Enter destination IP adress ")
        permit_icmp  += f"permit icmp any host {permit_icmp_dest}\n"  
        
    elif user_action == "3":
        permit_icmp_source = input("Enter source IP adress ")
        permit_icmp_dest  = input("Enter Destination IP adress ")
        permit_icmp += f"permit icmp host {permit_icmp_source} host {permit_icmp_dest}\n"
        
    elif user_action == "4":
        source_ip = input("Enter source IP adress: ")
        source_wildcard_masks =input("Enter source wildcard masks: ")
        destination_ip = input("Enter destination ip: ")
        destination_wildcard_masks =input("Enter destination wildcard masks: ")
        permit_icmp += f"permit icmp {source_ip} {source_wildcard_masks} {destination_ip} {destination_wildcard_masks}\n"              
        
    elif user_action == "5":     
        permit_icmp += f"permit icmp any any\n"
        
    elif user_action == "6":
        print("Exiting function...")
        exit
        
    else:
        print("Invalid selection. Please try again.")
             
    result = filtered_nr.run(task=send_command, command=permit_icmp)
    print_result(result)
    filtered_nr.close_connections()
        
def deny_domainname(filtered_nr, password):
    
    acl_name = input("Enter ACL name : ")
    print("Would you like to spacific \n 1.Source\n 2.Destination\n 3.Source and Destination\n 4.Range\n 5.Not specific\n 6.Exit\n ") 
    user_action = input("Choose action : ")
    
    deny_domainname = f"enable\n{password}\nconf t\n"
    deny_domainname += f"ip access-list extended {acl_name}\n"
    
    if user_action == "1":
        deny_domainname_source = input("Enter source IP adress ")
        deny_domainname += f"deny udp host {deny_domainname_source} eq 53 any\n"
        
    elif user_action == "2":
        deny_domainname_dest = input("Enter destination IP adress ")
        deny_domainname  += f"deny udp any eq 53 host {deny_domainname_dest}\n"  
        
    elif user_action == "3":
        deny_domainname_source = input("Enter source IP adress ")
        deny_domainname_dest  = input("Enter Destination IP adress ")
        deny_domainname += f"deny udp host {deny_domainname_source} eq 53 host {deny_domainname_dest}\n"
    
    elif user_action == "4":
        source_domainname = input("Enter source IP adress: ")
        source_wildcard_masks =input("Enter source wildcard masks: ")
        destination_domainname = input("Enter destination ip: ")
        destination_wildcard_masks =input("Enter destination wildcard masks: ")
        deny_domainname  += f"deny udp {source_domainname} {source_wildcard_masks} {destination_domainname} {destination_wildcard_masks}\n" 
            
    elif user_action == "5": 
        deny_domainname += f"deny udp any any eq 53\n"  
        
    elif user_action == "6":
        print("Exiting function...")
        exit
        
    else:
        print("Invalid selection. Please try again.")
    
    result = filtered_nr.run(task=send_command, command=deny_domainname)
    print_result(result)
    filtered_nr.close_connections()
    
def permit_domainname(filtered_nr, password):
    
    acl_name = input("Enter ACL name : ")
    print("Would you like to spacific \n 1.Source\n 2.Destination\n 3.Source and Destination\n 4.Range\n 5.Not specific\n 6.Exit\n ") 
    user_action = input("Choose action : ")
    
    permit_domainname = f"enable\n{password}\nconf t\n"
    permit_domainname += f"ip access-list extended {acl_name}\n"
    
    if user_action == "1":
        permit_domainname_source = input("Enter source IP adress ")
        permit_domainname += f"permit udp host {permit_domainname_source} eq 53 any\n"
        
    elif user_action == "2":
        permit_domainname_dest = input("Enter destination IP adress ")
        permit_domainname  += f"permit udp any eq 53 host {permit_domainname_dest}\n"  
        
    elif user_action == "3":
        permit_domainname_source = input("Enter source IP adress ")
        permit_domainname_dest  = input("Enter Destination IP adress ")
        permit_domainname += f"permit udp host {permit_domainname_source} eq 53 host {permit_domainname_dest}\n"
    
    elif user_action == "4":
        source_domainname = input("Enter source IP adress: ")
        source_wildcard_masks =input("Enter source wildcard masks: ")
        destination_domainname = input("Enter destination ip: ")
        destination_wildcard_masks =input("Enter destination wildcard masks: ")
        permit_domainname  += f"permit udp {source_domainname} {source_wildcard_masks} {destination_domainname} {destination_wildcard_masks}\n" 
            
    elif user_action == "5": 
        permit_domainname += f"permit udp any any eq 53\n"  
        
    elif user_action == "6":
        print("Exiting function...")
        exit
        
    else:
        print("Invalid selection. Please try again.")
    
    result = filtered_nr.run(task=send_command, command=permit_domainname)
    print_result(result)
    filtered_nr.close_connections()
 

def deny_tcp(filtered_nr, password):
    
    acl_name = input("Enter ACL name : ")
    print("Would you like to spacific \n 1.Source\n 2.Destination\n 3.Source and Destination\n 4.Range\n 5.Not specific\n 6.Exit \n")
    user_action = input("Choose action : ")
    
    deny_tcp = f"enable\n{password}\nconf t\n"
    deny_tcp += f"ip access-list extended {acl_name}\n"
    
    if user_action == "1":
        deny_sourcetcp = input("Enter source IP adress ")
        deny_tcp += f"deny tcp host {deny_sourcetcp}\n"
        
    elif user_action == "2":
        deny_destinationtcp = input("Enter destination IP adress ")
        deny_tcp  += f"deny tcp any host {deny_destinationtcp}\n"  
        
    elif user_action == "3":
        deny_sourcetcp = input("Enter source IP adress ")
        deny_destinationtcp  = input("Enter Destination IP adress ")
        deny_tcp += f"deny tcp host {deny_sourcetcp} host {deny_destinationtcp}\n"
        
    elif user_action == "4":
        source_tcp = input("Enter source IP adress: ")
        source_wildcard_masks =input("Enter source wildcard masks: ")
        destination_tcp = input("Enter destination ip: ")
        destination_wildcard_masks =input("Enter destination wildcard masks: ")
        deny_tcp  += f"deny tcp {source_tcp} {source_wildcard_masks} {destination_tcp} {destination_wildcard_masks}\n" 
        
    elif user_action == "5": 
        deny_tcp += f"deny tcp any any eq 80\n"  
        
    elif user_action == "6":
        print("Exiting function...")
        exit
        
    else:
        print("Invalid selection. Please try again.")
        
    result = filtered_nr.run(task=send_command, command=deny_tcp)
    print_result(result)
    filtered_nr.close_connections()
    
def permit_tcp(filtered_nr, password):
    
    acl_name = input("Enter ACL name : ")
    print("Would you like to spacific \n 1.Source\n 2.Destination\n 3.Source and Destination\n 4.Range\n 5.Not specific\n 6.Exit \n")
    user_action = input("Choose action : ")
    
    permit_tcp = f"enable\n{password}\nconf t\n"
    permit_tcp += f"ip access-list extended {acl_name}\n"
    
    if user_action == "1":
        permit_sourcetcp = input("Enter source IP adress ")
        permit_tcp += f"permit tcp host {permit_sourcetcp}\n"
        
    elif user_action == "2":
        permit_destinationtcp = input("Enter destination IP adress ")
        permit_tcp  += f"permit tcp any host {permit_destinationtcp}\n"  
        
    elif user_action == "3":
        permit_sourcetcp = input("Enter source IP adress ")
        permit_destinationtcp  = input("Enter Destination IP adress ")
        permit_tcp += f"permit tcp host {permit_sourcetcp} host {permit_destinationtcp}\n"
        
    elif user_action == "4":
        source_tcp = input("Enter source IP adress: ")
        source_wildcard_masks =input("Enter source wildcard masks: ")
        destination_tcp = input("Enter destination ip: ")
        destination_wildcard_masks =input("Enter destination wildcard masks: ")
        permit_ip  += f"permit tcp {source_tcp} {source_wildcard_masks} {destination_tcp} {destination_wildcard_masks}\n" 
        
    elif user_action == "5": 
        permit_tcp += f"permit tcp any any eq 80\n"  
        
    elif user_action == "6":
        print("Exiting function...")
        exit
        
    else:
        print("Invalid selection. Please try again.")
        
    result = filtered_nr.run(task=send_command, command=permit_tcp)
    print_result(result)
    filtered_nr.close_connections()
    
    
def deny_udp(filtered_nr, password):
    
    acl_name = input("Enter ACL name : ")
    print("Would you like to spacific \n 1.Source\n 2.Destination\n 3.Source and Destination\n 4.Range\n 5.Not specific \n 6.Exit \n")
    user_action = input("Choose action : ")

    deny_udp = f"enable\n{password}\nconf t\n"
    deny_udp += f"ip access-list extended {acl_name}\n"
    
    if user_action == "1":
        deny_sourceudp = input("Enter source IP adress ")
        deny_udp += f"deny udp host {deny_sourceudp}\n"
        
    elif user_action == "2":
        deny_destinationudp = input("Enter destination IP adress ")
        deny_udp  += f"deny udp any host {deny_destinationudp}\n"  
        
    elif user_action == "3":
        deny_sourceudp = input("Enter source IP adress ")
        deny_destinationudp  = input("Enter Destination IP adress ")
        deny_udp += f"deny udp host {deny_sourceudp} host {deny_destinationudp}\n"
        
    elif user_action == "4":
        source_udp = input("Enter source IP adress: ")
        source_wildcard_masks =input("Enter source wildcard masks: ")
        destination_udp = input("Enter destination ip: ")
        destination_wildcard_masks =input("Enter destination wildcard masks: ")
        deny_udp  += f"deny ip {source_udp} {source_wildcard_masks} {destination_udp} {destination_wildcard_masks}\n" 
        
    elif user_action == "5":
        deny_udp += f"deny udp any any eq 53\n" 
        
    elif user_action == "6":
        print("Exiting function...")
        exit
        
    else:
        print("Invalid selection. Please try again.")
  
    result = filtered_nr.run(task=send_command, command=deny_udp)
    print_result(result)
    filtered_nr.close_connections()
    
def permit_udp(filtered_nr, password):
    
    acl_name = input("Enter ACL name : ")
    print("Would you like to spacific \n 1.Source\n 2.Destination\n 3.Source and Destination\n 4.Range\n 5.Not specific \n 6.Exit \n")
    user_action = input("Choose action : ")

    permit_udp = f"enable\n{password}\nconf t\n"
    permit_udp += f"ip access-list extended {acl_name}\n"
    
    if user_action == "1":
        permit_sourceudp = input("Enter source IP adress ")
        permit_udp += f"permit udp host {permit_sourceudp}\n"
        
    elif user_action == "2":
        permit_destinationudp = input("Enter destination IP adress ")
        permit_udp  += f"permit udp any host {permit_destinationudp}\n"  
        
    elif user_action == "3":
        permit_sourceudp = input("Enter source IP adress ")
        permit_destinationudp  = input("Enter Destination IP adress ")
        permit_udp += f"permit udp host {permit_sourceudp} host {permit_destinationudp}\n"
        
    elif user_action == "4":
        source_udp = input("Enter source IP adress: ")
        source_wildcard_masks =input("Enter source wildcard masks: ")
        destination_udp = input("Enter destination ip: ")
        destination_wildcard_masks =input("Enter destination wildcard masks: ")
        permit_udp  += f"permit ip {source_udp} {source_wildcard_masks} {destination_udp} {destination_wildcard_masks}\n" 
        
    elif user_action == "5":
        permit_udp += f"permit udp any any eq 53\n" 
        
    elif user_action == "6":
        print("Exiting function...")
        exit
        
    else:
        print("Invalid selection. Please try again.")
  
    result = filtered_nr.run(task=send_command, command=permit_udp)
    print_result(result)
    filtered_nr.close_connections()


def deny_ip(filtered_nr, password):
    
    acl_name = input("Enter ACL name : ")    
    print("Would you like to spacific \n 1.Source\n 2.Destination\n 3.Source and Destination\n 4.Range\n 5.Not specific \n 6.Exit \n")
    user_action = input("Choose action : ")
    
    deny_ip = f"enable\n{password}\nconf t\n"
    deny_ip += f"ip access-list extended {acl_name}\n" 
       
    if user_action == "1":
        deny_sourceip = input("Enter source IP adress ")
        deny_ip += f"deny ip host {deny_sourceip}\n"  
            
    elif user_action == "2":
        deny_destinationip = input("Enter destination IP adress ")
        deny_ip  += f"deny ip any host {deny_destinationip}\n"     
        
    elif user_action == "3":
        deny_sourceip = input("Enter source IP adress ")
        deny_destinationip  = input("Enter Destination IP adress ")
        deny_ip += f"deny ip host {deny_sourceip} host {deny_destinationip}\n"
        
    elif user_action == "4":
        source_ip = input("Enter source IP adress: ")
        source_wildcard_masks =input("Enter source wildcard masks: ")
        destination_ip = input("Enter destination ip: ")
        destination_wildcard_masks =input("Enter destination wildcard masks: ")
        deny_ip  += f"deny ip {source_ip} {source_wildcard_masks} {destination_ip} {destination_wildcard_masks}\n"  
        
    elif user_action == "5":
        deny_ip += f"deny ip any any\n"
        
    elif user_action == "6":
        print("Exiting function...")
        exit
        
    else:
        print("Invalid selection. Please try again.")

    result = filtered_nr.run(task=send_command, command=deny_ip)
    print_result(result)
    filtered_nr.close_connections()         
    
def permit_ip(filtered_nr, password):
    
    acl_name = input("Enter ACL name : ")    
    print("Would you like to spacific \n 1.Source\n 2.Destination\n 3.Source and Destination\n 4.Range\n 5.Not specific \n 6.Exit \n")
    user_action = input("Choose action : ")
    permit_ip = f"enable\n{password}\nconf t\n"
    permit_ip += f"ip access-list extended {acl_name}\n" 
       
    if user_action == "1":
        permit_sourceip = input("Enter source IP adress ")
        permit_ip += f"permit ip host {permit_sourceip}\n"  
            
    elif user_action == "2":
        permit_destinationip = input("Enter destination IP adress ")
        permit_ip  += f"permit ip any host {permit_destinationip}\n"     
        
    elif user_action == "3":
        permit_sourceip = input("Enter source IP adress ")
        permit_destinationip  = input("Enter Destination IP adress ")
        permit_ip += f"permit ip host {permit_sourceip} host {permit_destinationip}\n"
        
    elif user_action == "4":
        source_ip = input("Enter source IP adress: ")
        source_wildcard_masks =input("Enter source wildcard masks: ")
        destination_ip = input("Enter destination ip: ")
        destination_wildcard_masks =input("Enter destination wildcard masks: ")
        permit_ip  += f"permit ip {source_ip} {source_wildcard_masks} {destination_ip} {destination_wildcard_masks}\n"  
        
    elif user_action == "5":
        deny_ip += f"deny ip any any\n"
         
    elif user_action == "6":
        print("Exiting function...")
        exit
        
    else:
        print("Invalid selection. Please try again.")

    result = filtered_nr.run(task=send_command, command=permit_ip)
    print_result(result)
    filtered_nr.close_connections()             

def inbound (filtered_nr, password):
    
    interface_inbound = input("Enter interface inbound: ")
    access_list_name = input("Enter Access list name: ")
    
    inbound = f"enable\n{password}\nconf t\n"
    
    inbound += f"interface {interface_inbound}\n"
    inbound += f"ip access-group {access_list_name} in\n"
    
    result = filtered_nr.run(task=send_command, command=inbound)
    print_result(result)
    filtered_nr.close_connections()    

def outbound (filtered_nr, password):
    
    interface_outbound = input("Enter interface outbound: ")
    access_list_name = input("Enter Access list name: ")
    
    outbound = f"enable\n{password}\nconf t\n"
    
    outbound += f"interface {interface_outbound}\n"
    outbound += f"ip access-group {access_list_name} out\n"
    
    result = filtered_nr.run(task=send_command, command=outbound)
    print_result(result)
    filtered_nr.close_connections()

def main():
    global passwords
    nr = InitNornir(config_file="config.yaml")

    while True:
        group_name = input("Enter the device group name: ")
        filtered_nr, hosts = filter_group(nr, group_name)

        if filtered_nr is not None:
            passwords = {}
            connected_devices = []  
            for host in hosts:
                host_ip = nr.inventory.hosts[host].hostname
                if test_connection(host_ip):  
                    password = getpass("Enter the password for device \033[33m{}\033[0m: ".format(host))
                    passwords[host] = password
                    connected_devices.append(host)  
                else:
                    print(f"\033[91mCannot connect to device {host} , skipping...\033[0m\n")

            if connected_devices:
                break
            else:
                print("No devices in this group could be connected to. Please choose another group.\n")
        else:
            print("Invalid device group. Please enter a valid group name.")

    while True:
        print("******************** "+"---- \033[92mDevice Group : "+ group_name +"\033[0m -----\n")
        print("1 Basic ACL")
        print("2 Advdance ACL")
        print("3 Delete ")
        print("4 Test & Result") 
        print("5 Show ACL") 
        print("6 Exit\n")
        print("********************")  
        
        user_action = input("Choose action : ")
        
        if user_action == "1":
            basic_acl(filtered_nr, password)
            
        elif user_action == "2":
            advdance_acl(filtered_nr, password) 
        
        elif user_action == "3":
            main_delete_acl(filtered_nr, password) 
            
        elif user_action == "4":
            inbound(filtered_nr, password)
            
        elif user_action == "5":
            show_acl(filtered_nr, password)
    
    
        elif user_action == "6":
            print("Exiting program...")
            break
        
        else:
            print("Invalid selection. Please try again.")

if __name__ == "__main__":
    main()