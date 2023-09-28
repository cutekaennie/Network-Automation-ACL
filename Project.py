from netmiko import ConnectHandler
from nornir import InitNornir
from nornir_utils.plugins.functions import print_result
from nornir.core.filter import F
from getpass import getpass
import logging 
import json
import re

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
    
def test_acl(acl_name,src_ip,filtered_nr):
    
    src =  src_ip
    print("src",src)
    global dest  
    dest = "192.168.35.141" 
    with open("./json_acl/acl_command.json", 'r') as file:
        existing_data = json.load(file) 
    data = existing_data[acl_name]
    for key, value in data.items():
        if key != "acl_name":
            ip = re.findall("\d+\.\d+\.\d+\.\d+", value)
            print(f"Key: {key}, Value: {ip}")
            
            if len(ip) > 0 :
                src = ip[0]
                dest = ip[len(ip)-1]
            test_acl_command = f"enable\n"    
            test_acl_command += f"ping {src}\n" 
            print("test_acl_command",test_acl_command)    
                    
            result = filtered_nr.run(task=send_command, command=test_acl_command)
            print_result(result)
            filtered_nr.close_connections()    
        
def show_acl(filtered_nr):
    show_acl ="enable\n"
    show_acl += f"show access-list"
    
    result = filtered_nr.run(task=send_command, command=show_acl)
    print_result(result)
    filtered_nr.close_connections()
    
def delete_on_interface (filtered_nr):
    delete_on_interface = "enable\nconf t\n"
    interface = input("Enter interface : ")
    delete_on_interface += f"int {interface}\n"
    delete_on_interface += f"do show ip access-group\n"
    acl_name = input("Enter ACL name : ")
     
    flow = input("Select direction of pecket flow (in / out): ")
    delete_on_interface += f"no ip access-group {acl_name} {flow}\n"
    
    result = filtered_nr.run(task=send_command, command=delete_on_interface)
    print_result(result)
    filtered_nr.close_connections()
def delete_some_line (filtered_nr): #no บันทัด ในsimใช่งานไม่ได้จริงเหมือนที่เรียนมา **ไปลองในห้องแลป**
    delete_some_line = "enable\nconf t\n"
    acl_name = input("Enter ACL name : ")
    delete_some_line += f"do show ip access-lists {acl_name}\n"
    line_number = input("Enter line number to delete : ")
    delete_some_line += f"no {line_number}\n"
    
    result = filtered_nr.run(task=send_command, command=delete_some_line)
    print_result(result)
    filtered_nr.close_connections()
    
def delete_acl(filtered_nr):
    delete_acl = "enable\nconf t\n"
    acl_name = input("Enter ACL name : ")
    delete_acl += f"no ip access-list extended {acl_name}"
    
    result = filtered_nr.run(task=send_command, command=delete_acl)
    print_result(result)
    filtered_nr.close_connections()
    
def modify(filtered_nr):
    print("1.Delete on interface")
    print("2.Delete some line")
    print("3.Delete ACL ")
    print("4.Exit \n")
    user_action = input("Choose action : ")
    
    if user_action == "1":
        delete_on_interface (filtered_nr)
        
    elif user_action == "2":
        delete_some_line (filtered_nr)
        
    elif user_action == "3":
        delete_acl(filtered_nr)
        
    elif user_action == "4":
        exit
def apply_acl (filtered_nr):
    print("======================================\n")
    print("Select direction of pecket flow ")
    print("1 Inbound")
    print("2 Outbound")
    print("3 Back main program to create acl again\n")
    
    user_action = input("Choose action : ")
    if user_action == "1":
        inbound(filtered_nr)
    elif user_action == "2":
        outbound(filtered_nr)  
    elif user_action == "3":
        exit
    print("======================================\n")
    
def basic_acl (filtered_nr):
    print("======================================\n")
    print("top 10 access control list for network\n")
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
    print("11 Exit\n")
    print("======================================")
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
    acl_config = {
    "acl_name": acl_name,
    "Block_a_specific_IP_address" : f"deny ip host {ip} any\n"
    }
    write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    result = filtered_nr.run(task=send_command, command=Block_a_specific_IP_address)
    print_result(result)
    filtered_nr.close_connections()
    
def Allow_SSH_from_a_specific_IP_Address(filtered_nr): 
    
    acl_name = input("Enter ACL name : ")
    Allow_SSH_from_a_specific_IP_Address = f"enable\nconf t\n"
    Allow_SSH_from_a_specific_IP_Address += f"ip access-list extended {acl_name}\n"
    
    ip = input("Enter IP adress ")
    Allow_SSH_from_a_specific_IP_Address += f"permit tcp host {ip} any eq 22\n"  
    acl_config = {
    "acl_name": acl_name,
    "Allow_SSH_from_a_specific_IP_Address" : f"permit tcp host {ip} any eq 22\n"
    }
    write_acl_to_json(acl_config, f"json_acl/acl_command.json")
    
    result = filtered_nr.run(task=send_command, command=Allow_SSH_from_a_specific_IP_Address)
    print_result(result)
    filtered_nr.close_connections()

def Deny_all_telnet_traffic(filtered_nr):     
    
    acl_name = input("Enter ACL name : ")
    Deny_all_telnet_traffic = f"enable\nconf t\n"
    Deny_all_telnet_traffic += f"ip access-list extended {acl_name}\n"
    
    Deny_all_telnet_traffic += f"deny tcp any any eq 23\n"
    acl_config = {
    "acl_name": acl_name,
    "Deny_all_telnet_traffic" : f"deny tcp any any eq 23\n"
    }
    write_acl_to_json(acl_config, f"json_acl/acl_command.json")
    
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
    acl_config = {
    "acl_name": acl_name,
    "Allow_web_traffic_HTTP_from_a_Subnet" : f"permit tcp {ip} {wildcard_masks} any eq 80\n"
    }
    write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
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
    acl_config = {
    "acl_name": acl_name,
    "Allow_Web_Traffic_HTTPS_from_a_Subnet" : f"permit tcp {ip} {wildcard_masks} any eq 443\n"
    }
    write_acl_to_json(acl_config, f"json_acl/acl_command.json")
     
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
    acl_config = {
    "acl_name": acl_name,
    "Block_All_Traffic_from_a_Specific_Subnet" : f"permit ip {ip} {wildcard_masks} any\n"
    }
    write_acl_to_json(acl_config, f"json_acl/acl_command.json")
    
    result = filtered_nr.run(task=send_command, command=Block_All_Traffic_from_a_Specific_Subnet)
    print_result(result)
    filtered_nr.close_connections()

def Allow_ICMP_for_Ping (filtered_nr): 
     
    acl_name = input("Enter ACL name : ")
    Allow_ICMP_for_Ping = f"enable\nconf t\n"
    Allow_ICMP_for_Ping += f"ip access-list extended {acl_name}\n"
    
    Allow_ICMP_for_Ping += f"permit icmp any any echo\n"
    acl_config = {
    "acl_name": acl_name,
    "Allow_ICMP_for_Ping" : f"permit icmp any any echo\n"
    }
    write_acl_to_json(acl_config, f"json_acl/acl_command.json")
    
    result = filtered_nr.run(task=send_command, command=Allow_ICMP_for_Ping)
    print_result(result)
    filtered_nr.close_connections()

def Deny_All_Traffic_to_a_Sensitive_Server (filtered_nr):  
        
    acl_name = input("Enter ACL name : ")
    Deny_All_Traffic_to_a_Sensitive_Server = f"enable\nconf t\n"
    Deny_All_Traffic_to_a_Sensitive_Server += f"ip access-list extended {acl_name}\n"
    
    ip = input("Enter sensitive IP adress: ")
    Deny_All_Traffic_to_a_Sensitive_Server += f"deny ip any host {ip}\n"
    acl_config = {
    "acl_name": acl_name,
    "Deny_All_Traffic_to_a_Sensitive_Server" : f"deny ip any host {ip}\n"
    }
    write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    result = filtered_nr.run(task=send_command, command=Deny_All_Traffic_to_a_Sensitive_Server)
    print_result(result)
    filtered_nr.close_connections()

def Allow_DNS_Queries (filtered_nr):
    
    acl_name = input("Enter ACL name : ")
    Allow_DNS_Queries = f"enable\nconf t\n"
    Allow_DNS_Queries += f"ip access-list extended {acl_name}\n"
    
    Allow_DNS_Queries += f"permit udp any any eq 53\n"
    acl_config = {
    "acl_name": acl_name,
    "Allow_DNS_Queries" : f"permit udp any any eq 53\n"
    }
    write_acl_to_json(acl_config, f"json_acl/acl_command.json")
     
    result = filtered_nr.run(task=send_command, command=Allow_DNS_Queries)
    print_result(result)
    filtered_nr.close_connections()

def Allow_DHCP_Responses(filtered_nr):
    
    acl_name = input("Enter ACL name : ")
    Allow_DHCP_Responses = f"enable\nconf t\n"
    Allow_DHCP_Responses += f"ip access-list extended {acl_name}\n"
    
    Allow_DHCP_Responses += f"permit udp any eq 67 any eq 68\n"  # 67 DHCP Server ,68 DHCP Client
    acl_config = {
    "acl_name": acl_name,
    "Allow_DHCP_Responses" : f"permit udp any eq 67 any eq 68\n"
    }
    write_acl_to_json(acl_config, f"json_acl/acl_command.json")
     
    result = filtered_nr.run(task=send_command, command=Allow_DHCP_Responses)
    print_result(result)
    filtered_nr.close_connections()

    
def advdance_acl(filtered_nr):
    print("======================================\n")
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
    print("11 Exit\n")
    print("======================================")
    user_action = input("Choose action : ")
        
    if user_action == "1":
        deny_icmp(filtered_nr)
        apply_acl (filtered_nr)
            
    elif user_action == "2":
        deny_domainname(filtered_nr) 
        apply_acl (filtered_nr)
        
    elif user_action == "3":
        deny_tcp(filtered_nr) 
        apply_acl (filtered_nr)
        
    elif user_action == "4":
        deny_udp(filtered_nr) 
        apply_acl (filtered_nr)
            
    elif user_action == "5":
        deny_ip(filtered_nr) 
        apply_acl (filtered_nr)
        
    elif user_action == "6":
        permit_icmp(filtered_nr) 
        apply_acl (filtered_nr)
            
    elif user_action == "7":
        permit_domainname(filtered_nr) 
        apply_acl (filtered_nr)
        
    elif user_action == "8":
        permit_tcp(filtered_nr) 
        apply_acl (filtered_nr)
            
    elif user_action == "9":
        permit_udp(filtered_nr) 
        apply_acl (filtered_nr)
        
    elif user_action == "10":
        permit_ip(filtered_nr) 
        apply_acl (filtered_nr)
        
    elif user_action == "11":
        print("Exiting program...")
        exit
        
    else:
        print("Invalid selection. Please try again.")
        
def write_acl_to_json(acl_config, filename):
    # with open(filename, 'w') as json_file:
        
    #     json.dump(acl_config, json_file, indent=4) 
    # Load the existing JSON file (if it exists)
    try:
        with open(filename, 'r') as file:
            existing_data = json.load(file)
    except FileNotFoundError:
        # If the file doesn't exist, create an empty dictionary
        existing_data = {}

    # Extract the "acl_name" from the input data
    acl_name = acl_config.get("acl_name")
    if acl_name in existing_data:
        existing_data[acl_name].update(acl_config)
        
    else :
        # Create a new entry with the "acl_name" as the key
        new_data = {acl_name:acl_config}

        # Update the existing dictionary with the new data
        existing_data.update(new_data)

        # Save the updated data back to the JSON file
    with open(filename, 'w') as file:
        json.dump(existing_data, file, indent=4)     
              
def deny_icmp(filtered_nr):
    acl_name = input("Enter ACL name : ")
    print("Would you like to spacific \n 1.Source\n 2.Destination\n 3.Source and Destination\n 4.Range\n 5.Not specific\n 6.Exit\n ")
    user_action = input("Choose action : ")
    
    deny_icmp = f"conf t\n"
    deny_icmp += f"ip access-list extended {acl_name}\n"
    
    if user_action == "1":
        deny_icmp_source = input("Enter source IP adress ")
        deny_icmp += f"deny icmp host {deny_icmp_source} any\n"
        acl_config = {
        "acl_name": acl_name,
        "deny_icmp_source" : f"deny icmp host {deny_icmp_source} any"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "2":
        deny_icmp_dest = input("Enter destination IP adress ")
        deny_icmp  += f"deny icmp any host {deny_icmp_dest}\n" 
        acl_config = {
        "acl_name": acl_name,
        "deny_icmp_dest" : f"deny icmp any host {deny_icmp_dest}"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json") 
        
    elif user_action == "3":
        deny_icmp_source = input("Enter source IP adress ")
        deny_icmp_dest  = input("Enter Destination IP adress ")
        deny_icmp += f"deny icmp host {deny_icmp_source} host {deny_icmp_dest}\n"
        acl_config = {
        "acl_name": acl_name,
        "deny_icmp_source_dest" : f"deny icmp host {deny_icmp_source} host {deny_icmp_dest}\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json") 
        
        
    elif user_action == "4":
        source_ip = input("Enter source IP adress: ")
        source_wildcard_masks =input("Enter source wildcard masks: ")
        destination_ip = input("Enter destination ip: ")
        destination_wildcard_masks =input("Enter destination wildcard masks: ")
        deny_icmp += f"deny icmp {source_ip} {source_wildcard_masks} {destination_ip} {destination_wildcard_masks}\n"      
        acl_config = {
        "acl_name": acl_name,
        "deny_icmp_range" : f"deny icmp {source_ip} {source_wildcard_masks} {destination_ip} {destination_wildcard_masks}\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")         
        
    elif user_action == "5":     
        deny_icmp += f"deny icmp any any\n"
        acl_config = {
        "acl_name": acl_name,
        "deny_icmp_not_specific" : f"deny icmp any any\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")       
        
    elif user_action == "6":
        print("Exiting function...")
        exit
        
    else:
        print("Invalid selection. Please try again.")
             
    result = filtered_nr.run(task=send_command, command=deny_icmp)
    print_result(result)
    filtered_nr.close_connections()
    


def permit_icmp(filtered_nr):
    acl_name = input("Enter ACL name : ")
    print("Would you like to spacific \n 1.Source\n 2.Destination\n 3.Source and Destination\n 4.Range\n 5.Not specific\n 6.Exit\n ")
    user_action = input("Choose action : ")
    
    permit_icmp = f"enable\nconf t\n"
    permit_icmp += f"ip access-list extended {acl_name}\n"
    
    if user_action == "1":
        permit_icmp_source = input("Enter source IP adress ")
        permit_icmp += f"permit icmp host {permit_icmp_source} any\n"
        acl_config = {
        "acl_name": acl_name,
        "permit_icmp_source" : f"permit icmp host {permit_icmp_source} any\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "2":
        permit_icmp_dest = input("Enter destination IP adress ")
        permit_icmp  += f"permit icmp any host {permit_icmp_dest}\n"  
        acl_config = {
        "acl_name": acl_name,
        "permit_icmp_dest" : f"permit icmp any host {permit_icmp_dest}\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "3":
        permit_icmp_source = input("Enter source IP adress ")
        permit_icmp_dest  = input("Enter Destination IP adress ")
        permit_icmp += f"permit icmp host {permit_icmp_source} host {permit_icmp_dest}\n"
        acl_config = {
        "acl_name": acl_name,
        "permit_icmp_source_dest" : f"permit icmp host {permit_icmp_source} host {permit_icmp_dest}\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "4":
        source_ip = input("Enter source IP adress: ")
        source_wildcard_masks =input("Enter source wildcard masks: ")
        destination_ip = input("Enter destination ip: ")
        destination_wildcard_masks =input("Enter destination wildcard masks: ")
        permit_icmp += f"permit icmp {source_ip} {source_wildcard_masks} {destination_ip} {destination_wildcard_masks}\n"              
        acl_config = {
        "acl_name": acl_name,
        "permit_icmp_range" : f"permit icmp {source_ip} {source_wildcard_masks} {destination_ip} {destination_wildcard_masks}\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
     
        
    elif user_action == "5":     
        permit_icmp += f"permit icmp any any\n"
        acl_config = {
        "acl_name": acl_name,
        "deny_icmp_not_specific" : f"permit icmp any any\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")     
        
    elif user_action == "6":
        print("Exiting function...")
        exit
        
    else:
        print("Invalid selection. Please try again.")
             
    result = filtered_nr.run(task=send_command, command=permit_icmp)
    print_result(result)
    filtered_nr.close_connections()
        
def deny_domainname(filtered_nr):
    
    acl_name = input("Enter ACL name : ")
    print("Would you like to spacific \n 1.Source\n 2.Destination\n 3.Source and Destination\n 4.Range\n 5.Not specific\n 6.Exit\n ") 
    user_action = input("Choose action : ")
    
    deny_domainname = f"enable\nconf t\n"
    deny_domainname += f"ip access-list extended {acl_name}\n"
    
    if user_action == "1":
        deny_domainname_source = input("Enter source IP adress ")
        deny_domainname += f"deny udp host {deny_domainname_source} eq 53 any\n"
        acl_config = {
        "acl_name": acl_name,
        "deny_domainname_source" : f"deny udp host {deny_domainname_source} eq 53 any\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "2":
        deny_domainname_dest = input("Enter destination IP adress ")
        deny_domainname  += f"deny udp any eq 53 host {deny_domainname_dest}\n"  
        acl_config = {
        "acl_name": acl_name,
        "deny_domainname_dest" : f"deny udp any eq 53 host {deny_domainname_dest}\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
        
    elif user_action == "3":
        deny_domainname_source = input("Enter source IP adress ")
        deny_domainname_dest  = input("Enter Destination IP adress ")
        deny_domainname += f"deny udp host {deny_domainname_source} eq 53 host {deny_domainname_dest}\n"
        acl_config = {
        "acl_name": acl_name,
        "ddeny_domainname_source_dest" : f"deny udp host {deny_domainname_source} eq 53 host {deny_domainname_dest}\n" 
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "4":
        source_domainname = input("Enter source IP adress: ")
        source_wildcard_masks =input("Enter source wildcard masks: ")
        destination_domainname = input("Enter destination ip: ")
        destination_wildcard_masks =input("Enter destination wildcard masks: ")
        deny_domainname  += f"deny udp {source_domainname} {source_wildcard_masks} {destination_domainname} {destination_wildcard_masks}\n" 
        acl_config = {
        "acl_name": acl_name,
        "deny_domainname_range" : f"deny udp {source_domainname} {source_wildcard_masks} {destination_domainname} {destination_wildcard_masks}\n"
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
                  
    elif user_action == "5": 
        deny_domainname += f"deny udp any any eq 53\n"  
        acl_config = {
        "acl_name": acl_name,
        "deny_domainname_not_specific" : f"deny udp any any eq 53\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")       
        
        
    elif user_action == "6":
        print("Exiting function...")
        exit
        
    else:
        print("Invalid selection. Please try again.")
    
    result = filtered_nr.run(task=send_command, command=deny_domainname)
    print_result(result)
    filtered_nr.close_connections()
    
def permit_domainname(filtered_nr):
    
    acl_name = input("Enter ACL name : ")
    print("Would you like to spacific \n 1.Source\n 2.Destination\n 3.Source and Destination\n 4.Range\n 5.Not specific\n 6.Exit\n ") 
    user_action = input("Choose action : ")
    
    permit_domainname = f"enable\nconf t\n"
    permit_domainname += f"ip access-list extended {acl_name}\n"
    
    if user_action == "1":
        permit_domainname_source = input("Enter source IP adress ")
        permit_domainname += f"permit udp host {permit_domainname_source} eq 53 any\n"
        acl_config = {
        "acl_name": acl_name,
        "permit_domainname_source" : f"permit udp host {permit_domainname_source} eq 53 any\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")    
        
    elif user_action == "2":
        permit_domainname_dest = input("Enter destination IP adress ")
        permit_domainname  += f"permit udp any eq 53 host {permit_domainname_dest}\n"  
        acl_config = {
        "acl_name": acl_name,
        "permit_domainname_dest" : f"permit udp any eq 53 host {permit_domainname_dest}\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")   
          
    elif user_action == "3":
        permit_domainname_source = input("Enter source IP adress ")
        permit_domainname_dest  = input("Enter Destination IP adress ")
        permit_domainname += f"permit udp host {permit_domainname_source} eq 53 host {permit_domainname_dest}\n"
        acl_config = {
        "acl_name": acl_name,
        "permit_domainname_source_dest" : f"permit udp host {permit_domainname_source} eq 53 host {permit_domainname_dest}\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")       
         
    elif user_action == "4":
        source_domainname = input("Enter source IP adress: ")
        source_wildcard_masks =input("Enter source wildcard masks: ")
        destination_domainname = input("Enter destination ip: ")
        destination_wildcard_masks =input("Enter destination wildcard masks: ")
        permit_domainname  += f"permit udp {source_domainname} {source_wildcard_masks} {destination_domainname} {destination_wildcard_masks}\n" 
        acl_config = {
        "acl_name": acl_name,
        "permit_domainname_range" : f"permit udp {source_domainname} {source_wildcard_masks} {destination_domainname} {destination_wildcard_masks}\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")        
         
            
    elif user_action == "5": 
        permit_domainname += f"permit udp any any eq 53\n"  
        acl_config = {
        "acl_name": acl_name,
        "permit_domainname_not_specific" : f"permit udp any any eq 53\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")         
         
    elif user_action == "6":
        print("Exiting function...")
        exit
        
    else:
        print("Invalid selection. Please try again.")
    
    result = filtered_nr.run(task=send_command, command=permit_domainname)
    print_result(result)
    filtered_nr.close_connections()
 

def deny_tcp(filtered_nr):
    
    acl_name = input("Enter ACL name : ")
    print("Would you like to spacific \n 1.Source\n 2.Destination\n 3.Source and Destination\n 4.Range\n 5.Not specific\n 6.Exit \n")
    user_action = input("Choose action : ")
    
    deny_tcp = f"enable\nconf t\n"
    deny_tcp += f"ip access-list extended {acl_name}\n"
    
    if user_action == "1":
        deny_sourcetcp = input("Enter source IP adress ")
        deny_tcp += f"deny tcp host {deny_sourcetcp}\n"
        acl_config = {
        "acl_name": acl_name,
        "deny_tcp_source" : f"deny tcp host {deny_sourcetcp}\n"
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "2":
        deny_destinationtcp = input("Enter destination IP adress ")
        deny_tcp  += f"deny tcp any host {deny_destinationtcp}\n"  
        acl_config = {
        "acl_name": acl_name,
        "deny_tcp_dest" : f"deny tcp any host {deny_destinationtcp}\n"
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
        
    elif user_action == "3":
        deny_sourcetcp = input("Enter source IP adress ")
        deny_destinationtcp  = input("Enter Destination IP adress ")
        deny_tcp += f"deny tcp host {deny_sourcetcp} host {deny_destinationtcp}\n"
        acl_config = {
        "acl_name": acl_name,
        "deny_tcp_source_dest" : f"deny tcp host {deny_sourcetcp} host {deny_destinationtcp}\n"     
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "4":
        source_tcp = input("Enter source IP adress: ")
        source_wildcard_masks =input("Enter source wildcard masks: ")
        destination_tcp = input("Enter destination ip: ")
        destination_wildcard_masks =input("Enter destination wildcard masks: ")
        deny_tcp  += f"deny tcp {source_tcp} {source_wildcard_masks} {destination_tcp} {destination_wildcard_masks}\n" 
        acl_config = {
        "acl_name": acl_name,
        "deny_tcp_range" : f"deny tcp {source_tcp} {source_wildcard_masks} {destination_tcp} {destination_wildcard_masks}\n"     
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json") 
        
    elif user_action == "5": 
        deny_tcp += f"deny tcp any any eq 80\n"  
        acl_config = {
        "acl_name": acl_name,
        "deny_tcp_not_specific" : f"deny tcp any any eq 80\n"     
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
        
    elif user_action == "6":
        print("Exiting function...")
        exit
        
    else:
        print("Invalid selection. Please try again.")
        
    result = filtered_nr.run(task=send_command, command=deny_tcp)
    print_result(result)
    filtered_nr.close_connections()
    
def permit_tcp(filtered_nr):
    
    acl_name = input("Enter ACL name : ")
    print("Would you like to spacific \n 1.Source\n 2.Destination\n 3.Source and Destination\n 4.Range\n 5.Not specific\n 6.Exit \n")
    user_action = input("Choose action : ")
    
    permit_tcp = f"enable\nconf t\n"
    permit_tcp += f"ip access-list extended {acl_name}\n"
    
    if user_action == "1":
        permit_sourcetcp = input("Enter source IP adress ")
        permit_tcp += f"permit tcp host {permit_sourcetcp}\n"
        acl_config = {
        "acl_name": acl_name,
        "permit_tcp_source" : f"permit tcp host {permit_sourcetcp}\n"     
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json") 
        
        
    elif user_action == "2":
        permit_destinationtcp = input("Enter destination IP adress ")
        permit_tcp  += f"permit tcp any host {permit_destinationtcp}\n"  
        acl_config = {
        "acl_name": acl_name,
        "permit_tcp_dest" : f"permit tcp any host {permit_destinationtcp}\n"     
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "3":
        permit_sourcetcp = input("Enter source IP adress ")
        permit_destinationtcp  = input("Enter Destination IP adress ")
        permit_tcp += f"permit tcp host {permit_sourcetcp} host {permit_destinationtcp}\n"
        acl_config = {
        "acl_name": acl_name,
        "permit_tcp_source_dest" : f"permit tcp host {permit_sourcetcp} host {permit_destinationtcp}\n"     
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "4":
        source_tcp = input("Enter source IP adress: ")
        source_wildcard_masks =input("Enter source wildcard masks: ")
        destination_tcp = input("Enter destination ip: ")
        destination_wildcard_masks =input("Enter destination wildcard masks: ")
        permit_ip  += f"permit tcp {source_tcp} {source_wildcard_masks} {destination_tcp} {destination_wildcard_masks}\n" 
        acl_config = {
        "acl_name": acl_name,
        "permit_tcp_range" : f"permit tcp {source_tcp} {source_wildcard_masks} {destination_tcp} {destination_wildcard_masks}\n"     
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "5": 
        permit_tcp += f"permit tcp any any eq 80\n"  
        acl_config = {
        "acl_name": acl_name,
        "permit_tcp_not_specific" : f"permit tcp any any eq 80\n"     
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "6":
        print("Exiting function...")
        exit
        
    else:
        print("Invalid selection. Please try again.")
        
    result = filtered_nr.run(task=send_command, command=permit_tcp)
    print_result(result)
    filtered_nr.close_connections()
    
    
def deny_udp(filtered_nr):
    
    acl_name = input("Enter ACL name : ")
    print("Would you like to spacific \n 1.Source\n 2.Destination\n 3.Source and Destination\n 4.Range\n 5.Not specific \n 6.Exit \n")
    user_action = input("Choose action : ")

    deny_udp = f"enable\nconf t\n"
    deny_udp += f"ip access-list extended {acl_name}\n"
    
    if user_action == "1":
        deny_sourceudp = input("Enter source IP adress ")
        deny_udp += f"deny udp host {deny_sourceudp}\n"
        acl_config = {
        "acl_name": acl_name,
        "deny_udp_source" : f"deny udp host {deny_sourceudp}\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "2":
        deny_destinationudp = input("Enter destination IP adress ")
        deny_udp  += f"deny udp any host {deny_destinationudp}\n"  
        acl_config = {
        "acl_name": acl_name,
        "deny_udp_dest" : f"deny udp any host {deny_destinationudp}\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "3":
        deny_sourceudp = input("Enter source IP adress ")
        deny_destinationudp  = input("Enter Destination IP adress ")
        deny_udp += f"deny udp host {deny_sourceudp} host {deny_destinationudp}\n"
        acl_config = {
        "acl_name": acl_name,
        "deny_udp_source_dest" : f"deny udp host {deny_sourceudp} host {deny_destinationudp}\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "4":
        source_udp = input("Enter source IP adress: ")
        source_wildcard_masks =input("Enter source wildcard masks: ")
        destination_udp = input("Enter destination ip: ")
        destination_wildcard_masks =input("Enter destination wildcard masks: ")
        deny_udp  += f"deny ip {source_udp} {source_wildcard_masks} {destination_udp} {destination_wildcard_masks}\n" 
        acl_config = {
        "acl_name": acl_name,
        "deny_udp_range" : f"deny ip {source_udp} {source_wildcard_masks} {destination_udp} {destination_wildcard_masks}\n"
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "5":
        deny_udp += f"deny udp any any eq 53\n" 
        acl_config = {
        "acl_name": acl_name,
        "deny_udp_not_specific" : f"deny udp any any eq 53\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")    
        
    elif user_action == "6":
        print("Exiting function...")
        exit
        
    else:
        print("Invalid selection. Please try again.")
  
    result = filtered_nr.run(task=send_command, command=deny_udp)
    print_result(result)
    filtered_nr.close_connections()
    
def permit_udp(filtered_nr):
    
    acl_name = input("Enter ACL name : ")
    print("Would you like to spacific \n 1.Source\n 2.Destination\n 3.Source and Destination\n 4.Range\n 5.Not specific \n 6.Exit \n")
    user_action = input("Choose action : ")

    permit_udp = f"enable\nconf t\n"
    permit_udp += f"ip access-list extended {acl_name}\n"
    
    if user_action == "1":
        permit_sourceudp = input("Enter source IP adress ")
        permit_udp += f"permit udp host {permit_sourceudp}\n"
        acl_config = {
        "acl_name": acl_name,
        "permit_udp_source" : f"permit udp host {permit_sourceudp}\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "2":
        permit_destinationudp = input("Enter destination IP adress ")
        permit_udp  += f"permit udp any host {permit_destinationudp}\n"  
        acl_config = {
        "acl_name": acl_name,
        "permit_udp_dest" : f"permit udp any host {permit_destinationudp}\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "3":
        permit_sourceudp = input("Enter source IP adress ")
        permit_destinationudp  = input("Enter Destination IP adress ")
        permit_udp += f"permit udp host {permit_sourceudp} host {permit_destinationudp}\n"
        acl_config = {
        "acl_name": acl_name,
        "permit_udp_source_dest" : f"permit udp host {permit_sourceudp} host {permit_destinationudp}\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "4":
        source_udp = input("Enter source IP adress: ")
        source_wildcard_masks =input("Enter source wildcard masks: ")
        destination_udp = input("Enter destination ip: ")
        destination_wildcard_masks =input("Enter destination wildcard masks: ")
        permit_udp  += f"permit ip {source_udp} {source_wildcard_masks} {destination_udp} {destination_wildcard_masks}\n" 
        acl_config = {
        "acl_name": acl_name,
        "permit_udp_range" : f"permit ip {source_udp} {source_wildcard_masks} {destination_udp} {destination_wildcard_masks}\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "5":
        permit_udp += f"permit udp any any eq 53\n" 
        acl_config = {
        "acl_name": acl_name,
        "permit_udp_not_specific" : f"permit udp any any eq 53\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "6":
        print("Exiting function...")
        exit
        
    else:
        print("Invalid selection. Please try again.")
  
    result = filtered_nr.run(task=send_command, command=permit_udp)
    print_result(result)
    filtered_nr.close_connections()


def deny_ip(filtered_nr):
    
    acl_name = input("Enter ACL name : ")    
    print("Would you like to spacific \n 1.Source\n 2.Destination\n 3.Source and Destination\n 4.Range\n 5.Not specific \n 6.Exit \n")
    user_action = input("Choose action : ")
    
    deny_ip = f"enable\nconf t\n"
    deny_ip += f"ip access-list extended {acl_name}\n" 
       
    if user_action == "1":
        deny_sourceip = input("Enter source IP adress ")
        deny_ip += f"deny ip host {deny_sourceip}\n"  
        acl_config = {
        "acl_name": acl_name,
        "deny_ip_source" : f"deny ip host {deny_sourceip}\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
            
    elif user_action == "2":
        deny_destinationip = input("Enter destination IP adress ")
        deny_ip  += f"deny ip any host {deny_destinationip}\n"     
        acl_config = {
        "acl_name": acl_name,
        "deny_ip_dest" : f"deny ip any host {deny_destinationip}\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
          
    elif user_action == "3":
        deny_sourceip = input("Enter source IP adress ")
        deny_destinationip  = input("Enter Destination IP adress ")
        deny_ip += f"deny ip host {deny_sourceip} host {deny_destinationip}\n"
        acl_config = {
        "acl_name": acl_name,
        "deny_ip_source_dest" : f"deny ip host {deny_sourceip} host {deny_destinationip}\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
         
    elif user_action == "4":
        source_ip = input("Enter source IP adress: ")
        source_wildcard_masks =input("Enter source wildcard masks: ")
        destination_ip = input("Enter destination ip: ")
        destination_wildcard_masks =input("Enter destination wildcard masks: ")
        deny_ip  += f"deny ip {source_ip} {source_wildcard_masks} {destination_ip} {destination_wildcard_masks}\n"  
        acl_config = {
        "acl_name": acl_name,
        "deny_ip_range" : f"deny ip {source_ip} {source_wildcard_masks} {destination_ip} {destination_wildcard_masks}\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
         
    elif user_action == "5":
        deny_ip += f"deny ip any any\n"
        acl_config = {
        "acl_name": acl_name,
        "deny_ip_not_specific" : f"deny ip any any\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
         
    elif user_action == "6":
        print("Exiting function...")
        exit
        
    else:
        print("Invalid selection. Please try again.")

    result = filtered_nr.run(task=send_command, command=deny_ip)
    print_result(result)
    filtered_nr.close_connections()         
    
def permit_ip(filtered_nr):
    
    acl_name = input("Enter ACL name : ")    
    print("Would you like to spacific \n 1.Source\n 2.Destination\n 3.Source and Destination\n 4.Range\n 5.Not specific \n 6.Exit \n")
    user_action = input("Choose action : ")
    permit_ip = f"enable\nconf t\n"
    permit_ip += f"ip access-list extended {acl_name}\n" 
       
    if user_action == "1":
        permit_sourceip = input("Enter source IP adress ")
        permit_ip += f"permit ip host {permit_sourceip}\n"  
        acl_config = {
        "acl_name": acl_name,
        "permit_ip_source" : f"permit ip host {permit_sourceip}\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
            
    elif user_action == "2":
        permit_destinationip = input("Enter destination IP adress ")
        permit_ip  += f"permit ip any host {permit_destinationip}\n"     
        acl_config = {
        "acl_name": acl_name,
        "permit_ip_dest" : f"permit ip any host {permit_destinationip}\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
         
    elif user_action == "3":
        permit_sourceip = input("Enter source IP adress ")
        permit_destinationip  = input("Enter Destination IP adress ")
        permit_ip += f"permit ip host {permit_sourceip} host {permit_destinationip}\n"
        acl_config = {
        "acl_name": acl_name,
        "permit_ip_dest" : f"permit ip host {permit_sourceip} host {permit_destinationip}\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
         
    elif user_action == "4":
        source_ip = input("Enter source IP adress: ")
        source_wildcard_masks =input("Enter source wildcard masks: ")
        destination_ip = input("Enter destination ip: ")
        destination_wildcard_masks =input("Enter destination wildcard masks: ")
        permit_ip  += f"permit ip {source_ip} {source_wildcard_masks} {destination_ip} {destination_wildcard_masks}\n"  
        acl_config = {
        "acl_name": acl_name,
        "permit_ip_range" : f"permit ip {source_ip} {source_wildcard_masks} {destination_ip} {destination_wildcard_masks}\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "5":
        deny_ip += f"deny ip any any\n"
        acl_config = {
        "acl_name": acl_name,
        "permit_ip_not_specific" : f"deny ip any any\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
         
    elif user_action == "6":
        print("Exiting function...")
        exit
        
    else:
        print("Invalid selection. Please try again.")

    result = filtered_nr.run(task=send_command, command=permit_ip)
    print_result(result)
    filtered_nr.close_connections()             

def inbound (filtered_nr):
    
    interface_inbound = input("Enter interface inbound: ")
    access_list_name = input("Enter Access list name: ")
    
    inbound = f"enable\nconf t\n"
    
    inbound += f"interface {interface_inbound}\n"
    inbound += f"ip access-group {access_list_name} in\n"
    
    result = filtered_nr.run(task=send_command, command=inbound)
    print_result(result)
    filtered_nr.close_connections()    

def outbound (filtered_nr):
    
    interface_outbound = input("Enter interface outbound: ")
    access_list_name = input("Enter Access list name: ")
    
    outbound = f"enable\nconf t\n"
    
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
        print(list(hosts.keys())[0])
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
        print("3 Modify ")
        print("4 Apply ACL ")
        print("5 Test & Result") 
        print("6 Show ACL") 
        print("7 Exit\n")
        print("********************")  
        
        user_action = input("Choose action : ")
        
        if user_action == "1":
            basic_acl(filtered_nr)
            
        elif user_action == "2":
            advdance_acl(filtered_nr) 
        
        elif user_action == "3":
            modify(filtered_nr) 
            
        elif user_action == "4":
            apply_acl(filtered_nr)
            
        elif user_action == "5": 
            acl_name = input("Enter ACL name : ")
            
            filtered_nr = nr.filter(F(groups__contains=group_name))
            hosts = filtered_nr.inventory.hosts
            host_user_name = (list(hosts.keys())[0])
            src_ip = hosts[host_user_name].hostname 
            test_acl(acl_name,src_ip,filtered_nr)
            
    
        elif user_action == "6":
            show_acl(filtered_nr)
    
        elif user_action == "6":
            print("Exiting program...")
            break
        
        else:
            print("Invalid selection. Please try again.")

if __name__ == "__main__":
    main()