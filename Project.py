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
    with open("./json_acl/acl_command.json", 'r') as file:
        existing_data = json.load(file) 
    data = existing_data[acl_name]

    for idx, (key, value) in enumerate(data.items()):
        src =  ""
        dest = "" 
        port = ""
        
        if key != "acl_name":
            pattern = r'\d+\.\d+\.\d+\.\d+'
            # port_pattern = r'\d+'
            allowed_ports = r'(80|443|53|23)'

            ip = re.findall(pattern, value)
            portMatch = re.findall(allowed_ports, value)

            print(f"case: {idx+1}")
            print(f"Key: {key}, Value: {ip}")
        
            l = len(ip)
            
            if l == 4:
                src = ip[0]
                dest = ip[2]
            elif l > 1 and l < 4:
                if re.search(f'(\s) (ip|tcp) {pattern} {pattern} any', value):
                    src = ip[0]
                else:   
                    src = ip[0]
                    if l > 1:
                        dest = ip[1]
            else:
                if re.search(f'host {pattern} any', value):
                    # src = ip[0]
                    src = ip[0]
                elif re.search(f'any host {pattern}', value):
                    dest = ip[0]
                else:
                    ip_from_user = input("Input for test: ")
                    src = ip_from_user 
                    # dest = ""

            if re.search(f'eq {allowed_ports}', value):
                port = portMatch[0]
                # print("port:",portMatch)

            test_acl_command = "enable\n"
            
            if key == "icmp" or key == "ip":
                test_acl_command += f"ping {src or dest}\n" 
            elif key == "tcp":
                if port == "23":
                    test_acl_command +=  f"telnet {src or dest} {port}\n" 
                elif port == "80":
                    test_acl_command +=  f"ping Web.ac.th\n" 
                elif port == "443":
                    test_acl_command +=  f"ping https://www.sut.ac.th\n"
            else:
                test_acl_command +=  f"ping a.ac.th\n" 

            print(f"Source IP: {src}")
            print(f"Destination IP: {dest}")
            print(f"Port: {port}")
            print(f"{test_acl_command}\n")

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
    # delete_on_interface += f"do show ip access-group\n"
    acl_name = input("Enter ACL name : ")
     
    flow = input("Select direction of pecket flow (in / out): ")
    delete_on_interface += f"no ip access-group {acl_name} {flow}\n"
    
    result = filtered_nr.run(task=send_command, command=delete_on_interface)
    print_result(result)
    filtered_nr.close_connections()
    
def delete_some_line (filtered_nr):
    delete_some_line = "enable\nconf t\n"
    acl_name = input("Enter ACL name : ")
    delete_some_line += f"ip access-list extended {acl_name}\n"
    line_number = input("Enter line number to delete : ")
    delete_some_line += f"no {line_number}\n"
    print(line_number)
    
    # e.g., 10 -> 1 100 -> 10
    # {
    #   idx:0  "acl_name": "test1",
    #   idx: 1  "deny_icmp_source": "deny icmp host 192.168.35.141 any",
    #   idx: 2 "permit_ip_not_specific": "permit ip any any\n"
    # }
    split_idx = int(line_number[:-1])
    print(split_idx)
    delete_acl_line_number_from_json(acl_name, index=split_idx, filename="./json_acl/acl_command.json", filename_for_get_key="./json_acl/acl_command_for_get_key.json")
    
    result = filtered_nr.run(task=send_command, command=delete_some_line)
    print_result(result)
    filtered_nr.close_connections()
      
    
def delete_acl_line_number_from_json(acl_name, index,filename, filename_for_get_key):
    try:
        # Load the existing JSON file (if it exists)
        with open(filename_for_get_key, 'r') as file:
            existing_data_get_key = json.load(file)

        # Load file for get key of acl cmd
        with open(filename, 'r') as file:
            existing_data = json.load(file)
        
    except FileNotFoundError:
        # If the file doesn't exist, there's nothing to delete
        print(f"ACL '{acl_name}' not found in the JSON file.")
        return

    # Check if the ACL name exists in the JSON data
    if acl_name in existing_data:
        # Delete the ACL entry from the dictionary

        k = list(existing_data_get_key[acl_name])[index]

        print(f"key of {acl_name}: {k}")
        del existing_data[acl_name][k]
        
        # Save the updated data back to the JSON file
        with open(filename, 'w') as file:
            json.dump(existing_data, file, indent=4)
        print(f"ACL '{acl_name}' deleted from the JSON file.")
    else:
        print(f"ACL '{acl_name}' not found in the JSON file.")

def delete_acl_from_json(acl_name, filename):
    try:
        # Load the existing JSON file (if it exists)
        with open(filename, 'r') as file:
            existing_data = json.load(file)
    except FileNotFoundError:
        # If the file doesn't exist, there's nothing to delete
        print(f"ACL '{acl_name}' not found in the JSON file.")
        return

    # Check if the ACL name exists in the JSON data
    if acl_name in existing_data:
        # Delete the ACL entry from the dictionary

        del existing_data[acl_name]

        # k = list(existing_data[acl_name])[index]
        # print(f"key of {acl_name}: {k}")
        # del existing_data[acl_name][k]
        
        # Save the updated data back to the JSON file
        with open(filename, 'w') as file:
            json.dump(existing_data, file, indent=4)
        print(f"ACL '{acl_name}' deleted from the JSON file.")
    else:
        print(f"ACL '{acl_name}' not found in the JSON file.")
             
def delete_acl(filtered_nr):
    delete_acl = "enable\nconf t\n"
    acl_name = input("Enter ACL name : ")
    delete_acl += f"no ip access-list extended {acl_name}"
    
    result = filtered_nr.run(task=send_command, command=delete_acl)
    delete_acl_from_json(acl_name, filename="./json_acl/acl_command.json")
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
        
def write_acl_to_json(acl_config, filename):
    split_filename = filename.split(".json")

    file_get_key = f"{split_filename[0]}_for_get_key.json"
    # print(split_filename)
    # with open(filename, 'w') as json_file:
        
    #     json.dump(acl_config, json_file, indent=4) 
    # Load the existing JSON file (if it exists)
    try:
        with open(filename, 'r') as file:
            existing_data = json.load(file)

        with open(file_get_key, 'r') as file_key:
            existing_data_get_key = json.load(file_key)
    except FileNotFoundError:
        # If the file doesn't exist, create an empty dictionary
        existing_data = {}
        existing_data_get_key = {}

    # Extract the "acl_name" from the input data
    acl_name = acl_config.get("acl_name")
    if acl_name in existing_data and acl_name in existing_data_get_key :
        existing_data[acl_name].update(acl_config)
        existing_data_get_key[acl_name].update(acl_config)
        
    else :
        # Create a new entry with the "acl_name" as the key
        new_data = {acl_name:acl_config}

        # Update the existing dictionary with the new data
        existing_data.update(new_data)
        existing_data_get_key.update(new_data)

        # Save the updated data back to the JSON file
    with open(filename, 'w') as file:
        json.dump(existing_data, file, indent=4)   

    # duplicate file for get key of acl cmd
    with open(file_get_key, 'w') as file:
        json.dump(existing_data_get_key, file, indent=4)
    
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
 
def Create_ACL (filtered_nr):
    print("********************") 
    print("Enter Protocol\n")
    print("1 ICMP")
    print("2 UDP ")
    print("3 TCP ")
    print("4 IP") 
    print("5 DNS") 
    print("6 Exit\n")
    print("********************")  
       
    user_action = input("Choose action : ")
    if user_action == "1":
        protocol_icmp(filtered_nr)
        apply_acl (filtered_nr)
            
    elif user_action == "2":
        protocol_udp(filtered_nr) 
        apply_acl (filtered_nr)
        
    elif user_action == "3":
        protocol_tcp(filtered_nr) 
        apply_acl (filtered_nr)
            
    elif user_action == "4":
        protocol_ip(filtered_nr)
        apply_acl (filtered_nr)
        
    elif user_action == "5":
        protocol_dns(filtered_nr)
        apply_acl (filtered_nr)
        
    elif user_action == "6":
        print("Exiting program...")
        exit
        
    
def protocol_icmp (filtered_nr):
    print("Select action (default is 'permit'): ")  
    print("1 Permit")
    print("2 Deny\n")
    
    tmp = ""
    while not tmp:
        action = input("Choose action: ")
        if action == "1":
            tmp += "permit"
        elif action == "2":
            tmp += "deny"
        else:
            print("Invalid selection. Please try again.")
    
    print("Would you like to spacific \n 1.Source\n 2.Destination\n 3.Source and Destination\n 4.Range\n 5.Not specific\n 6.Exit\n ")
    user_action = input("Choose action : ")
    
    icmp = f"enable\nconf t\n"
    acl_name = input("Enter ACL name : ")
    icmp += f"ip access-list extended {acl_name}\n"
    
    if user_action == "1":
        icmp_source = input("Enter source IP adress ")
        icmp += f"{tmp} icmp host {icmp_source} any\n"
        acl_config = {
        "acl_name": acl_name,
        "icmp" : f"{tmp} icmp host {icmp_source} any\n"
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "2":
        icmp_dest = input("Enter destination IP adress ")
        icmp  += f"{tmp} icmp any host {icmp_dest}\n"  
        acl_config = {
        "acl_name": acl_name,
        "icmp" : f"{tmp} icmp any host {icmp_dest}\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "3":
        icmp_source = input("Enter source IP adress ")
        icmp_dest  = input("Enter Destination IP adress ")
        icmp += f"{tmp} icmp host {icmp_source} host {icmp_dest}\n"
        acl_config = {
        "acl_name": acl_name,
        "icmp" : f"{tmp} icmp host {icmp_source} host {icmp_dest}\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "4":
        source_ip = input("Enter source IP adress: ")
        source_wildcard_masks =input("Enter source wildcard masks: ")
        destination_ip = input("Enter destination ip: ")
        destination_wildcard_masks =input("Enter destination wildcard masks: ")
        icmp += f"{tmp} icmp {source_ip} {source_wildcard_masks} {destination_ip} {destination_wildcard_masks}\n"              
        acl_config = {
        "acl_name": acl_name,
        "icmp" : f"{tmp} icmp {source_ip} {source_wildcard_masks} {destination_ip} {destination_wildcard_masks}\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
     
        
    elif user_action == "5":     
        icmp += f"{tmp} icmp any any\n"
        acl_config = {
        "acl_name": acl_name,
        "icmp" : f"{tmp} icmp any any\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")     
        
    elif user_action == "6":
        print("Exiting function...")
        exit
        
    else:
        print("Invalid selection. Please try again.")
             
    result = filtered_nr.run(task=send_command, command=icmp)
    print_result(result)
    filtered_nr.close_connections()

def protocol_udp (filtered_nr):
    print("Select action (default is 'permit'): ")  
    print("1 Permit")
    print("2 Deny\n") 
    
    tmp = ""
    while not tmp:
        action = input("Choose action: ")
        if action == "1":
            tmp += "permit"
        elif action == "2":
            tmp += "deny"
        else:
            print("Invalid selection. Please try again.")
    
    print("Would you like to spacific \n 1.Source\n 2.Destination\n 3.Source and Destination\n 4.Range\n 5.Not specific\n 6.Exit\n ")
    user_action = input("Choose action : ")
    
    udp = f"enable\nconf t\n"
    acl_name = input("Enter ACL name : ")
    udp += f"ip access-list extended {acl_name}\n"
    
    if user_action == "1":
        permit_sourceudp = input("Enter source IP adress ")
        udp += f"{tmp} udp host {permit_sourceudp} any eq 53\n"
        acl_config = {
        "acl_name": acl_name,
        "udp" : f"{tmp} udp host {permit_sourceudp} any eq 53\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "2":
        permit_destinationudp = input("Enter destination IP adress ")
        udp  += f"{tmp} udp any host {permit_destinationudp} eq 53\n"  
        acl_config = {
        "acl_name": acl_name,
        "udp" : f"{tmp} udp any host {permit_destinationudp} eq 53\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "3":
        permit_sourceudp = input("Enter source IP adress ")
        permit_destinationudp  = input("Enter Destination IP adress ")
        udp += f"{tmp} udp host {permit_sourceudp} host {permit_destinationudp} eq 53\n"
        acl_config = {
        "acl_name": acl_name,
        "udp" : f"{tmp} udp host {permit_sourceudp} host {permit_destinationudp} eq 53\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "4":
        source_udp = input("Enter source IP adress: ")
        source_wildcard_masks =input("Enter source wildcard masks: ")
        destination_udp = input("Enter destination ip: ")
        destination_wildcard_masks =input("Enter destination wildcard masks: ")
        udp  += f"{tmp} ip {source_udp} {source_wildcard_masks} {destination_udp} {destination_wildcard_masks} eq 53\n" 
        acl_config = {
        "acl_name": acl_name,
        "udp" : f"{tmp} ip {source_udp} {source_wildcard_masks} {destination_udp} {destination_wildcard_masks} eq 53\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "5":
        permit_udp += f"{tmp} udp any any eq 53\n" 
        acl_config = {
        "acl_name": acl_name,
        "udp" : f"{tmp} udp any any eq 53\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "6":
        print("Exiting function...")
        exit
        
    else:
        print("Invalid selection. Please try again.")
  
    result = filtered_nr.run(task=send_command, command=udp)
    print_result(result)
    filtered_nr.close_connections()

def protocol_tcp (filtered_nr):
    print("Select action (default is 'permit'): ")  
    print("1 Permit")
    print("2 Deny\n")
    
    tmp = ""
    while not tmp:
        action = input("Choose action: ")
        if action == "1":
            tmp += "permit"
        elif action == "2":
            tmp += "deny"
        else:
            print("Invalid selection. Please try again.")
            
    print("Select Port : ")  
    print("1 23 = telnet")
    print("2 80 = HTTP")
    print("3 443 = HTTPS\n")
    
    tmpport = ""
    while not tmpport:
        action = input("Choose action: ")
        if action == "1":
            tmpport += "23"
        elif action == "2":
            tmpport += "80"
        elif action == "3":
            tmpport += "443"    
        else:
            print("Invalid selection. Please try again.")
    
    print("Would you like to spacific \n 1.Source\n 2.Destination\n 3.Source and Destination\n 4.Range\n 5.Not specific\n 6.Exit\n ")
    user_action = input("Choose action : ")
    
    tcp = f"enable\nconf t\n"
    acl_name = input("Enter ACL name : ")
    tcp += f"ip access-list extended {acl_name}\n"
    
    if user_action == "1":
        deny_sourcetcp = input("Enter source IP adress ")
        tcp += f"{tmp} tcp host {deny_sourcetcp} any eq {tmpport}\n"
        acl_config = {
        "acl_name": acl_name,
        "tcp" : f"{tmp} tcp host {deny_sourcetcp} any eq {tmpport}\n"
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "2":
        deny_destinationtcp = input("Enter destination IP adress ")
        tcp  += f"{tmp} tcp any host {deny_destinationtcp} eq {tmpport}\n"  
        acl_config = {
        "acl_name": acl_name,
        "tcp" : f"{tmp} tcp any host {deny_destinationtcp} eq {tmpport}\n"
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
        
    elif user_action == "3":
        deny_sourcetcp = input("Enter source IP adress ")
        deny_destinationtcp  = input("Enter Destination IP adress ")
        tcp += f"{tmp} tcp host {deny_sourcetcp} host {deny_destinationtcp} eq {tmpport}\n"
        acl_config = {
        "acl_name": acl_name,
        "tcp" : f"{tmp} tcp host {deny_sourcetcp} host {deny_destinationtcp} eq {tmpport}\n"     
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "4":
        source_tcp = input("Enter source IP adress: ")
        source_wildcard_masks =input("Enter source wildcard masks: ")
        destination_tcp = input("Enter destination ip: ")
        destination_wildcard_masks =input("Enter destination wildcard masks: ")
        tcp  += f"{tmp} tcp {source_tcp} {source_wildcard_masks} {destination_tcp} {destination_wildcard_masks} eq {tmpport}\n" 
        acl_config = {
        "acl_name": acl_name,
        "deny_tcp_range" : f"{tmp} tcp {source_tcp} {source_wildcard_masks} {destination_tcp} {destination_wildcard_masks} eq {tmpport}\n"     
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json") 
        
    elif user_action == "5": 
        tcp += f"{tmp} tcp any any eq {tmpport}\n"  
        acl_config = {
        "acl_name": acl_name,
        "tcp" : f"{tmp} tcp any any eq {tmpport}\n"     
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
        
    elif user_action == "6":
        print("Exiting function...")
        exit
        
    else:
        print("Invalid selection. Please try again.")
        
    result = filtered_nr.run(task=send_command, command=tcp)
    print_result(result)
    filtered_nr.close_connections()
    
def protocol_ip (filtered_nr):
    print("Select action (default is 'permit'): ")  
    print("1 Permit")
    print("2 Deny\n")
    
    tmp = ""
    while not tmp:
        action = input("Choose action: ")
        if action == "1":
            tmp += "permit"
        elif action == "2":
            tmp += "deny"
        else:
            print("Invalid selection. Please try again.")
    
    print("Would you like to spacific \n 1.Source\n 2.Destination\n 3.Source and Destination\n 4.Range\n 5.Not specific\n 6.Exit\n ")
    user_action = input("Choose action : ")
    
    ip = f"enable\nconf t\n"
    acl_name = input("Enter ACL name : ")
    ip += f"ip access-list extended {acl_name}\n"    
    
    if user_action == "1":
        deny_sourceip = input("Enter source IP adress ")
        ip += f"{tmp} ip host {deny_sourceip} any\n"  
        acl_config = {
        "acl_name": acl_name,
        "ip" : f"{tmp} ip host {deny_sourceip} any\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
            
    elif user_action == "2":
        deny_destinationip = input("Enter destination IP adress ")
        ip  += f"{tmp} ip any host {deny_destinationip}\n"     
        acl_config = {
        "acl_name": acl_name,
        "ip" : f"{tmp} ip any host {deny_destinationip}\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
          
    elif user_action == "3":
        deny_sourceip = input("Enter source IP adress ")
        deny_destinationip  = input("Enter Destination IP adress ")
        ip += f"{tmp} ip host {deny_sourceip} host {deny_destinationip}\n"
        acl_config = {
        "acl_name": acl_name,
        "ip" : f"{tmp} ip host {deny_sourceip} host {deny_destinationip}\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
         
    elif user_action == "4":
        source_ip = input("Enter source IP adress: ")
        source_wildcard_masks =input("Enter source wildcard masks: ")
        destination_ip = input("Enter destination ip: ")
        destination_wildcard_masks =input("Enter destination wildcard masks: ")
        ip  += f"{tmp} ip {source_ip} {source_wildcard_masks} {destination_ip} {destination_wildcard_masks}\n"  
        acl_config = {
        "acl_name": acl_name,
        "ip" : f"{tmp} ip {source_ip} {source_wildcard_masks} {destination_ip} {destination_wildcard_masks}\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
         
    elif user_action == "5":
        ip += f"{tmp} ip any any\n"
        acl_config = {
        "acl_name": acl_name,
        "ip" : f"{tmp} ip any any\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
         
    elif user_action == "6":
        print("Exiting function...")
        exit
        
    else:
        print("Invalid selection. Please try again.")

    result = filtered_nr.run(task=send_command, command=ip)
    print_result(result)
    filtered_nr.close_connections()         

def protocol_dns (filtered_nr):
    print("Select action (default is 'permit'): ")  
    print("1 Permit")
    print("2 Deny\n")
    
    tmp = ""
    while not tmp:
        action = input("Choose action: ")
        if action == "1":
            tmp += "permit"
        elif action == "2":
            tmp += "deny"
        else:
            print("Invalid selection. Please try again.")
    
    print("Would you like to spacific \n 1.Source\n 2.Destination\n 3.Source and Destination\n 4.Range\n 5.Not specific\n 6.Exit\n ")
    user_action = input("Choose action : ")
    
    dns = f"enable\nconf t\n"
    acl_name = input("Enter ACL name : ")
    dns += f"ip access-list extended {acl_name}\n"
    
    
    if user_action == "1":
        deny_domainname_source = input("Enter source IP adress ")
        dns += f"{tmp} udp host {deny_domainname_source} any eq 53 \n"
        acl_config = {
        "acl_name": acl_name,
        "dns" : f"{tmp} udp host {deny_domainname_source} any eq 53 \n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "2":
        deny_domainname_dest = input("Enter destination IP adress ")
        dns  += f"{tmp} udp any host {deny_domainname_dest} eq 53\n"  
        acl_config = {
        "acl_name": acl_name,
        "dns" : f"{tmp} udp any host {deny_domainname_dest} eq 53\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
        
    elif user_action == "3":
        deny_domainname_source = input("Enter source IP adress ")
        deny_domainname_dest  = input("Enter Destination IP adress ")
        dns += f"{tmp} udp host {deny_domainname_source} host {deny_domainname_dest} eq 53\n"
        acl_config = {
        "acl_name": acl_name,
        "dns" : f"{tmp} udp host {deny_domainname_source} host {deny_domainname_dest} eq 53\n" 
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
    elif user_action == "4":
        source_domainname = input("Enter source IP adress: ")
        source_wildcard_masks =input("Enter source wildcard masks: ")
        destination_domainname = input("Enter destination ip: ")
        destination_wildcard_masks =input("Enter destination wildcard masks: ")
        dns  += f"{tmp} udp {source_domainname} {source_wildcard_masks} {destination_domainname} {destination_wildcard_masks}\n" 
        acl_config = {
        "acl_name": acl_name,
        "dns" : f"{tmp} udp {source_domainname} {source_wildcard_masks} {destination_domainname} {destination_wildcard_masks}\n"
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")
        
                  
    elif user_action == "5": 
        dns += f"{tmp} udp any any eq 53\n"  
        acl_config = {
        "acl_name": acl_name,
        "dns" : f"{tmp} udp any any eq 53\n"
        
        }
        write_acl_to_json(acl_config, f"json_acl/acl_command.json")       
        
        
    elif user_action == "6":
        print("Exiting function...")
        exit
        
    else:
        print("Invalid selection. Please try again.")
    
    result = filtered_nr.run(task=send_command, command=dns)
    print_result(result)
    filtered_nr.close_connections()

 
def manual_config (filtered_nr):
    
    manual = f"enable\nconf t\n"
    acl_name = input("Enter ACL name : ")
    manual += f"ip access-list extended {acl_name}\n"
    manual_config = input("Enter manual config ACL : ")
    manual += f"{manual_config}\n"
    acl_config = {
    "acl_name": acl_name,
    "manual" : f"{manual_config}\n"
    }
    write_acl_to_json(acl_config, f"json_acl/acl_command.json")
     
             
    result = filtered_nr.run(task=send_command, command=manual)
    print_result(result)
    filtered_nr.close_connections()   
    
     
def change_device_group(nr):
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
                return group_name, filtered_nr
            else:
                print("No devices in this group could be connected to. Please choose another group.\n")
        else:
            print("Invalid device group. Please enter a valid group name.")

def main():
    global passwords
    nr = InitNornir(config_file="config.yaml")
    
    while True:
        group_name = input("Enter the device group name: ")
        filtered_nr, hosts = filter_group(nr, group_name)
        #print(list(hosts.keys())[0])
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
        print("1 Create ACL")
        print("2 Modify")
        print("3 Apply ACL ")
        print("4 Test & Result ")
        print("5 Show ACL") 
        print("6 Change device") 
        print("7 Manual config") 
        print("8 Exit\n")
        print("********************")  
        
        user_action = input("Choose action : ")
        
        if user_action == "1":
            Create_ACL(filtered_nr)
            
        elif user_action == "2":
            modify(filtered_nr) 
        
        elif user_action == "3":
            apply_acl(filtered_nr) 
            
        elif user_action == "4": 
            acl_name = input("Enter ACL name : ")
            
            filtered_nr = nr.filter(F(groups__contains=group_name))
            hosts = filtered_nr.inventory.hosts
            host_user_name = (list(hosts.keys())[0])
            src_ip = hosts[host_user_name].hostname 
            test_acl(acl_name,src_ip,filtered_nr)
            
    
        elif user_action == "5":
            show_acl(filtered_nr)
            
        elif user_action == "6":
            group_name, filtered_nr =change_device_group(filtered_nr) 
        
        elif user_action == "7":
            manual_config(filtered_nr)
            
        elif user_action == "8":
            print("Exiting program...")
            break
        
        else:
            print("Invalid selection. Please try again.")

if __name__ == "__main__":
    main()