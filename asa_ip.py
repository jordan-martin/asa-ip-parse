'''
Name: asa_ip.py
Description: Python script to discover all references to a specific IP address in an ASA configuration
Requires: Python 'sys', 'datetime', 're', 'ipaddress' and 'ciscoconfparse' libraries

Usage information for asa_ip.py:  


     python asa_ip.py <arguments>


     -s <source configuration file>   **Required**
     -o <output file>   **Only used when a single IP address is provided**
     -i <IP Address>
     -l <IP Address List File>   **One IP Address Per Line**


     Either -i or -l is required, but only one can be used

'''

import sys
import datetime
import re
import ipaddress
from ciscoconfparse import CiscoConfParse


# Function to parse the full configuration into dictionaries/lists that we will later use for analysis. Returns a bunch of lists and dictionaries.
def parse_asa_configuration(input_raw,input_parse):
    # Set up lists and dictionaries for return purposes
    names = []
    objects = {}
    object_groups = {}
    access_lists = []
    object_nat = {}
    static_nat = []
    # Read each line of the config, looking for configuratio components that we care about
    for line in input_raw:
        # Identify all staticallly configured name/IPAddress translations
        if re.match("^name (([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]).*",line):
            names.append(line)

        # Identify and collect configurations for all configured objects
        if 'object network' in line:
            obj = input_parse.find_children_w_parents(line,'^(?! nat ?.*)')
            obj_name = (line.split()).pop(2)
            if not obj_name in objects and obj:
                objects[obj_name] = (obj)

        # Identify and collect configurations for all configured object groups
        if 'object-group network' in line:
            obj_group = input_parse.find_children_w_parents(line,'.*')
            obj_group_name = (line.split()).pop(2)
            if not obj_group_name in object_groups and obj_group:
                object_groups[obj_group_name] = (obj_group)

        # Identify and collect configurations for all configured access lists
        if re.match("^access-list .*",line):
            access_lists.append(line)

        # Identify and collect configurations for all configured object NATs
        if 'object network' in line:
            obj_nat = input_parse.find_children_w_parents(line,'^ nat .*')
            obj_nat_name = (line.split()).pop(2)
            if not obj_nat_name in object_nat and obj_nat:
                object_nat[obj_nat_name] = (obj_nat)

        # Identify and collect configurations for all configured static NATs
        if re.match("^nat .*",line):
            static_nat.append(line)
    # Return all these things. At this point we aren't being discriminate. These are a raw collections of all items.
    return(names,objects,object_groups,access_lists,object_nat,static_nat)


# Function to check names for references to the provided IP address. Returns a list.
def check_names(input_names,ip_address):
    valid_names = []
    for item in input_names:
        if item.split()[1] == ip_address:
            valid_names.append(item.split()[2])
    return(valid_names)


# Function to check objects for references to the provided IP address or matches for any matched name. Returns a list.
def check_objects(input_objects,input_names,ip_address):
    valid_objects = []
    for k,v in input_objects.items():
        for item in v:
            # There are multiple possible configurations. Host, subnet and range. We need to validate if our IP Address is in any of them.
            if 'host' in item:
                # This one is simple.  Check to see if a host IP matches directly or if it matches a matched name.
                if item.split()[1] == ip_address:
                    valid_objects.append(k)
                for name in input_names:
                    if item.split()[1] == name:
                        valid_objects.append(k)
            if 'subnet' in item:
                # Here it requires a bit more work. We use the ipaddress library to validate if the IP resides within the network statement.
                network = unicode(item.split()[1] + "/" + item.split()[2],"utf-8")
                ipa = unicode(ip_address,"utf-8")
                if ipaddress.ip_address(ipa) in ipaddress.ip_network(network):
                    valid_objects.append(k)
            if 'range' in item:
                # This one was tricky. Since a range doesn't necessarily line up 1-for-1 with subnets, I used a summarization function in the ipaddress
                # library to generate a list of summaries required to cover the range of addresses provided in the object.  I then check our 
                # IP address against that list (ike the block above) to see if it resides in any of the summaries.  
                ipa = unicode(ip_address,"utf-8")
                first = unicode(item.split()[1],"utf-8")
                last = unicode(item.split()[2],"utf-8")
                subnets = [] 
                for ipaddr in ipaddress.summarize_address_range(ipaddress.IPv4Address(first),ipaddress.IPv4Address(last)):
                    if ipaddress.ip_address(ipa) in ipaddr:
                        valid_objects.append(k)
    return(valid_objects)


# Function to check object-groups for references to the provided IP address
def check_object_groups(input_object_groups,input_names,input_objects,ip_address):
    # Now we're cooking with fire. Again we have multiple possible config statements under the object-group config and we need
    # to match against all of them. We are working our way down the heirarchy from more specific to less spacific, so we can use
    # previous matches to determine if an object, name, or host configuration is relevant to our IP address.
    valid_object_groups = []
    recursive_groups = {}
    for k,v in input_object_groups.items():
        for item in v:
            # Right off the bat we have to start dealing with a mess. Object-groups can be nested. Those nested groups are relevant
            # to our IP address so we need to pull configs referencing them as well.
            if 'group-object' in item:
                if k in recursive_groups.keys():
                    recursive_groups[k].append(item.split()[1])
                if not k in recursive_groups.keys():
                    recursive_groups[k] = []
                    recursive_groups[k].append(item.split()[1])
            # Check a host/name reference against already matched lists
            if 'network-object host' in item:
                if item.split()[2] in input_names:
                    if k not in valid_object_groups:
                        valid_object_groups.append(k)
                if item.split()[2] == ip_address:
                    if k not in valid_object_groups:
                        valid_object_groups.append(k)
            # Check object references against already matched objects
            if 'network-object object' in item:
                if item.split()[2] in input_objects:
                    if k not in valid_object_groups:
                        valid_object_groups.append(k)
            # Identify network statements that are independent of objects and see if our IP address lies within their range.
            if re.match("^ network-object (([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]).*",item):
                network = unicode(item.split()[1] + "/" + item.split()[2],"utf-8")
                ipa = unicode(ip_address,"utf-8")
                if ipaddress.ip_address(ipa) in ipaddress.ip_network(network):
                    if k not in valid_object_groups:
                        valid_object_groups.append(k)
        # If any of our relevant object-groups had a nested-group, add it to the list of relevant object-groups.
        if k in valid_object_groups and k in recursive_groups.keys():
            for addons in recursive_groups[k]:
                if addons not in valid_object_groups:
                    valid_object_groups.append(addons)
    return(valid_object_groups)


# Function to check for recursive object-group references to those object-groups that matched the supplied IP Address
def check_recursive_object_groups(input_object_groups,matched_object_groups):
    recursive_reference = []
    for k,v in input_object_groups.items():
        for item in v:
            for matched_item in matched_object_groups:
                if 'group-object' in item and item.split()[1] == matched_item and k not in recursive_reference:
                    recursive_reference.append(k)
    return(recursive_reference)


# Function to check access-lists against previously discovered names, objects, object-groups and the provided IP address
def check_access_lists(input_access_lists,input_names,input_objects,input_object_groups,ip_address):
    valid_access_lists = {}
    for acl in input_access_lists:
        # We have to use enumerate here because I need to be able to reference the next word in the sentence so I need an accurate index.
        for i,v in enumerate(acl.split()):
            # Looking for specific key words in the ACL
            # Host is always followed by a single IP address so check to see if the next work matches the supplied IP Address or a matched name.
            if v == 'host':
                for names in input_names:
                    # Have to check for the existence of a next word.  Sometimes, including the test file I was working with, host is the last word
                    # in an ACL remark, which makes this script puke all over itself.  Better safe than sorry.
                    if (i+1) < len(acl.split()):
                        if acl.split()[i+1] == names:
                            if acl.split()[1] in valid_access_lists.keys():
                                valid_access_lists[acl.split()[1]].append(acl)
                            if not acl.split()[1] in valid_access_lists.keys():
                                valid_access_lists[acl.split()[1]] = []
                                valid_access_lists[acl.split()[1]].append(acl)
                if (i+1) < len(acl.split()):
                    if acl.split()[i+1] == ip_address:
                        if acl.split()[1] in valid_access_lists.keys():
                            valid_access_lists[acl.split()[1]].append(acl)
                        if not acl.split()[1] in valid_access_lists.keys():
                            valid_access_lists[acl.split()[1]] = []
                            valid_access_lists[acl.split()[1]].append(acl)
            # Here we're looking for the object key word and the following word will be an object.  We then check that againast our matched objects.
            if v == 'object':
                for objects in input_objects:
                    if (i+1) < len(acl.split()):
                        if acl.split()[i+1] == objects:
                            if acl.split()[1] in valid_access_lists.keys():
                                valid_access_lists[acl.split()[1]].append(acl)
                            if not acl.split()[1] in valid_access_lists.keys():
                                valid_access_lists[acl.split()[1]] = []
                                valid_access_lists[acl.split()[1]].append(acl)
            # Same as the object routine above.
            if v == 'object-group':
                for object_groups in input_object_groups:
                    if (i+1) < len(acl.split()):
                        if acl.split()[i+1] == object_groups:
                            if acl.split()[1] in valid_access_lists.keys():
                                valid_access_lists[acl.split()[1]].append(acl)
                            if not acl.split()[1] in valid_access_lists.keys():
                                valid_access_lists[acl.split()[1]] = []
                                valid_access_lists[acl.split()[1]].append(acl)
            # Here we're looking for IP ranges directly configured in the ACL.  Use regex to match an IP address or subnet mask.
            if re.match("(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])",v):
                if (i+1) < len(acl.split()):
                    if re.match("(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])",acl.split()[i+1]):
                        network = unicode(v + "/" + acl.split()[i+1],"utf-8")
                        ipa = unicode(ip_address,"utf-8")
                        # The problem here is that we can match on a mask and then an IP so we don't know if we have a valid IP/Mask combo.
                        # In order to not have the script fall apart when this happens, I'm just catching the exception and moving on.  The IPAddress
                        # library returns a ValueError if the network is represnted in a Mask/IPAddress format.  We just ignore these instances.
                        # Probably not the cleanest option but it works for now.
                        try:
                            if ipaddress.ip_address(ipa) in ipaddress.ip_network(network):
                                if acl.split()[1] in valid_access_lists.keys():
                                    valid_access_lists[acl.split()[1]].append(acl)
                                if not acl.split()[1] in valid_access_lists.keys():
                                    valid_access_lists[acl.split()[1]] = []
                                    valid_access_lists[acl.split()[1]].append(acl)
                        except ValueError:
                            continue
            # We have to include any/any ACLs as well since they technicaly match all addresses.
            if v == 'any':
                if (i+1) < len(acl.split()):
                    if acl.split()[i+1] == 'any':
                        if acl.split()[1] in valid_access_lists.keys():
                            valid_access_lists[acl.split()[1]].append(acl)
                        if not acl.split()[1] in valid_access_lists.keys():
                            valid_access_lists[acl.split()[1]] = []
                            valid_access_lists[acl.split()[1]].append(acl)
    return(valid_access_lists)


# Function to look for object NAT statements for the relevant objects we've previously discovered
def check_object_nat(input_object_nat,input_objects):
    valid_object_nat = []
    for nat in input_object_nat:
        if nat in input_objects:
            valid_object_nat.append(nat)
    return(valid_object_nat)


# Function to identify static NAT statements utilizing any relevant configurations we've identified previously
def check_static_nat(input_static_nat,input_objects,input_object_groups,ip_address):
    # This is currently overly simplistic and only factors in objects/object-groups that are referenced in NAT statements
    # It certainly needs to be refined for more definitive results.  Use at your own risk.  Who am I kidding, this whole script is use at your own risk.
    valid_static_nat = []
    for line in input_static_nat:
        for i,word in enumerate(line.split()):
            if word in input_objects:
                valid_static_nat.append(line)
            if word in input_object_groups:
                valid_static_nat.append(line)
    return(valid_static_nat)


# Function to write an output file(s) if requested
def write_to_file(multiple,output_file,input_parse,input_names,input_objects,input_object_groups,input_access_lists,input_object_nat,input_static_nat,ip_address):
    today = datetime.date.today()
    if multiple:
        filename = ip_address.split('.')[0] + "-" + ip_address.split('.')[1] + "-" + ip_address.split('.')[2] + "-" + ip_address.split('.')[3] + ".txt"
        f = open(filename,'w')
    else:
        if output_file:
            f = open(output_file,'w')
        else:
            f = open("output.txt",'w')
    f.write("Output returned for asa_ip.py script\n")
    f.write("IP Address Provided:  " + ip_address + "\n")
    f.write("Date:  " + today.ctime() + "\n\n\n")

    # Name Output
    if input_names:
        f.write("-----------------------------------------------------------------------------------------\n")
        f.write("\tMatched Name To IP Mappings Statically Configured\n")
        f.write("-----------------------------------------------------------------------------------------\n\n")
        for name in input_names:
            f.write("\t\t" + name)
        f.write("\n\n")

    # Object Output
    if input_objects:
        f.write("-----------------------------------------------------------------------------------------\n")
        f.write("\tMatched Objects\n")
        f.write("-----------------------------------------------------------------------------------------\n\n")
        for objects in input_objects:
            objects_cli = input_parse.find_all_children('object network ' + objects)
            for cli in objects_cli:
                f.write("\t\t" + cli)
        f.write("\n\n")

    # Object-Group Output
    if input_object_groups:
        f.write("-----------------------------------------------------------------------------------------\n")
        f.write("\tMatched Object-Groups\n")
        f.write("-----------------------------------------------------------------------------------------\n\n")
        for object_groups in input_object_groups:
            object_groups_cli = input_parse.find_all_children('object-group network ' + object_groups)
            for cli in object_groups_cli:
                f.write("\t\t" + cli)
        f.write("\n\n")

    # ACL Output
    if input_access_lists:
        f.write("-----------------------------------------------------------------------------------------\n")
        f.write("\tMatched Access-Lists\n")
        f.write("-----------------------------------------------------------------------------------------\n\n")
        for acl_name,acl_values in input_access_lists.items():
            f.write("\t--------------------------------------------\n")
            f.write("\tAccess-List:  " + acl_name + "\n")
            f.write("\t--------------------------------------------\n\n")
            for line in acl_values:
                f.write("\t\t" + line)
            f.write("\n\n")
        f.write("\n\n")

    # Object NAT Output
    if input_object_nat:
        f.write("-----------------------------------------------------------------------------------------\n")
        f.write("\tMatched Object NATs\n")
        f.write("-----------------------------------------------------------------------------------------\n\n")
        for object_nat in input_object_nat:
            object_nat_cli = input_parse.find_children_w_parents('object network ' + object_nat,'^ nat .*')
            if object_nat_cli:
                f.write("\t\tobject network " + object_nat + "\n")
                for line in object_nat_cli:
                    f.write("\t\t" + line)
        f.write("\n\n")

    # Static NAT Output
    if input_static_nat:
        f.write("-----------------------------------------------------------------------------------------\n")
        f.write("\tMatched Static NATs\n")
        f.write("-----------------------------------------------------------------------------------------\n\n")
        for static_nat in input_static_nat:
            f.write("\t\t" + static_nat)
        f.write("\n\n")

    f.close()


# Function to output script usage information
def print_usage():
    print("Usage information for asa_ip.py:  \n\n")
    print("     python asa_ip.py <arguments>\n\n")
    print("     -s <source configuration file>   **Required**")
    print("     -o <output file>   **Only used when a single IP address is provided**")
    print("     -i <IP Address>")
    print("     -l <IP Address List File>   **One IP Address Per Line**")
    print("\n")
    print("     Either -i or -l is required, but only one can be used\n\n\n")


def main():
    multiple = False
    user_output_file = "output.txt"
    if '-s' not in sys.argv:
        # Bail Out - Required
        print("\nScript Execution Halted - No Source File Provided\n\n")
        print_usage()
        raise SystemExit(0)
    if '-i' not in sys.argv and '-l' not in sys.argv:
        print("\nScript Execution Halted - No IP Address or Address File Provided\n\n")
        print_usage()
        raise SystemExit(0)
    if '-i' in sys.argv and '-l' in sys.argv:
        # Bail Out - We can't have it both ways
        print("\nScript Execution Halted - Both an IP Address and an Address File were provided. You can only use one or the other.\n\n")
        print_usage()
        raise SystemExit(0)
    for index,argument in enumerate(sys.argv):
        # Bring In User Supplied IP Address
        if argument == '-i':
            if (index+1) < len(sys.argv):
                if re.match("(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])",sys.argv[index+1]):
                    user_ip_address = sys.argv[index+1]
                else:
                    print("\nScript Execution Halted - The provided IP Address does not conform to the standard format.\n\n")
                    print_usage()
                    raise SystemExit(0)
            else:
                # Bail out - Need a valid IP address after the -i argument
                print("\nScript Execution Halted - No valid IP Address provided\n\n")
                print_usage()
                raise SystemExit(0)
        if argument == '-l':
            if (index+1) < len(sys.argv):
                user_ip_file = sys.argv[index+1]
                multiple = True
            else:
                # Bail out - need a valid IP list after the -l argument
                print("\nScript Execution Halted - No Address File provided\n\n")
                print_usage()
                raise SystemExit(0)
        if argument == '-o':
            if (index+1) < len(sys.argv):
                user_output_file = sys.argv[index+1]
            else:
                # Bail out - need a valid output file after the -o argument
                print("\nScript Execution Halted - No Output file provided\n\n")
                print_usage()
                raise SystemExit(0)
        if argument == '-s':
            if (index+1) < len(sys.argv):
                user_source_file = sys.argv[index+1]
            else:
                # Bail out - need a valid source configuration file after the -s argument
                print("\nScript Execution Halted - No Source Configuration provided\n\n")
                print_usage()
                raise SystemExit(0)

    # Open the source configuration file for reading and import/parse it.
    x = open(user_source_file,'r')
    config_raw = x.readlines()
    config_parse = CiscoConfParse(config_raw) 
    x.close()

    # Send configuration off to get split up into different lists/dictionaries for reference
    ret_names, ret_objects, ret_object_groups, ret_access_lists, ret_object_nat, ret_static_nat = parse_asa_configuration(config_raw,config_parse)

    # If we're using multiple IP addresses, set up a loop to run through them.  Otherwise use the provided address
    if multiple:
        i = open(user_ip_file,'r')
        addresses = i.readlines()
        # Verify that all IP Addresses are actually IP addresses
        for verification in addresses:
            if re.match("(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])",verification.rstrip('\n')):
                continue
            else:
                print("\nScript Execution Halted - At least one IP address in the Address File does not conform to the standard format.\n\n")
                print_usage()
                raise SystemExit(0)
        # Now loop through each address in the file and process the information.
        for address in addresses:
            print("Now working on:  " + address)
            print("Checking names...")
            conf_names = check_names(ret_names,address.rstrip('\n'))
            print("Checking objects...")
            conf_objects = check_objects(ret_objects,ret_names,address.rstrip('\n'))
            print("Checking object groups...")
            conf_object_groups = check_object_groups(ret_object_groups,conf_names,conf_objects,address.rstrip('\n'))
            conf_recursive_object_groups = check_recursive_object_groups(ret_object_groups,conf_object_groups)
            merged_object_groups = conf_object_groups + conf_recursive_object_groups
            print("Checking access-lists...")
            conf_access_lists = check_access_lists(ret_access_lists,conf_names,conf_objects,merged_object_groups,address.rstrip('\n'))
            print("Checking object NAT...")
            conf_object_nat = check_object_nat(ret_object_nat,conf_objects)
            print("Checking static NAT...")
            conf_static_nat = check_static_nat(ret_static_nat,conf_objects,merged_object_groups,address.rstrip('\n'))
            print("Writing output file...")
            write_to_file(multiple,user_output_file,config_parse,conf_names,conf_objects,merged_object_groups,conf_access_lists,conf_object_nat,conf_static_nat,address.rstrip('\n'))
    else:
        # Since we just have one ip address, we'll use the input from above and do the processing.
        print("Now working on:  " + user_ip_address)
        print("Checking names...")
        conf_names = check_names(ret_names,user_ip_address)
        print("Checking objects...")
        conf_objects = check_objects(ret_objects,ret_names,user_ip_address)
        print("Checking object groups...")
        conf_object_groups = check_object_groups(ret_object_groups,conf_names,conf_objects,user_ip_address)
        conf_recursive_object_groups = check_recursive_object_groups(ret_object_groups,conf_object_groups)
        merged_object_groups = conf_object_groups + conf_recursive_object_groups
        print("Checking access-lists...")
        conf_access_lists = check_access_lists(ret_access_lists,conf_names,conf_objects,merged_object_groups,user_ip_address)
        print("Checking object NAT...")
        conf_object_nat = check_object_nat(ret_object_nat,conf_objects)
        print("Checking static NAT...")
        conf_static_nat = check_static_nat(ret_static_nat,conf_objects,merged_object_groups,user_ip_address)
        print("Writing output file...")
        write_to_file(multiple,user_output_file,config_parse,conf_names,conf_objects,merged_object_groups,conf_access_lists,conf_object_nat,conf_static_nat,user_ip_address)


if __name__ == '__main__':
  main()
