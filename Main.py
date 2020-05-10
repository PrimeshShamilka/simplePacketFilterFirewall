'''
   Copyright (c) 2020, Primesh Shamilka,
   email: primeshs.17@cse.mrt.ac.lk
   All rights reserved. https://github.com/PrimeshShamilka/
   
   Revision history:
	  May 10th, 2020: initial version.
'''

import json
import dpkt
import socket
from filterRule_reader import get_rules

interface = ""
direction = ""
interface_name = ""

#
#
# packet_header data structure
#
#

packet_header = {"direction":'',
                "src_addr":'',
                "dest_addr":'',
                "protocol":'',
                "src_port":'',
                "dest_port":''}

filtering_rules = []


def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)



#
#
# call get_rules to get filtering rules from the config file
#
#

filtering_rules = get_rules()


#
#
# FUNCTION to log output 
#
#

def log_output(packet_header, action):

    global direction
    log_file = open('/media/primesh/F4D0EA80D0EA4906/PROJECTS/firewall/firewall/log.txt','a')
    
    if packet_header.get("protocol") == "IP":
        if direction == "INBOUND":
            result = direction + ": " + packet_header.get("protocol") + " packet " + action + " from " +  packet_header.get("src_addr") + "\n"
        elif direction == "OUTBOUND":
            result = direction + ": " + packet_header.get("protocol") + " packet " + action + " to " +  packet_header.get("dest_addr") + "\n"
    else:
        if direction == "INBOUND":
            result = direction + ": " + packet_header.get("protocol") + " packet " + action + " on port " +  packet_header.get("dest_port") + "\n"
        elif direction == "OUTBOUND":
            result = direction + ": " + packet_header.get("protocol") + " packet " + action + " on port " +  packet_header.get("src_port") + "\n"

    log_file.write(result)
    log_file.close()
#
#
# FUNCTION to match a filtering rule
#
#

def match(filtering_rule, packet_header):

    for field, value in filtering_rule.items():
        if (field == "rule_id"):
            continue
        elif (field == "action"):
            continue
        elif (value == "any"):
            continue
        elif (value == "EITHER"):
            continue
        elif (value != packet_header.get(field)):
            break
    else:
        return True

    return False

#
#
# FUNCTIONS to accept or reject packets based on filtering rules, rule that match first is the winner
#
#

def accept_or_reject(packet_header):

    global filtering_rules

    for rule in filtering_rules:
        print(rule)
        flag = match(rule, packet_header)
        print (flag)
        if flag == True:
            print (rule.get("action"))
            log_output(packet_header, rule.get("action"))
            break
    else:
        print ("No rule matching!.")

#
#
# READ packet headers from interface1 & interface2 sequintially
#
#


print ("Type A for interface1 or B for interface2")
usr_inpt = input()
if usr_inpt == 'A':
    interface_file = open('/media/primesh/F4D0EA80D0EA4906/PROJECTS/firewall/firewall/udp_file.pcap','rb')
    interface = dpkt.pcap.Reader(interface_file)
    direction = "INBOUND"
    interface_name = "INTERFACE1"
elif usr_inpt == 'B':
    interface_file = open('/media/primesh/F4D0EA80D0EA4906/PROJECTS/firewall/firewall/ip_file.pcap','rb')
    interface = dpkt.pcap.Reader(interface_file)
    direction = "OUTBOUND"
    interface_name = "INTERFACE2"


for ts, buf in interface:

    src_addr = ""
    dest_addr = ""
    protocol = ""
    src_port = ""
    dest_port = ""

    eth_packet = dpkt.ethernet.Ethernet(buf)

    # Make sure the Ethernet frame contains an IP packet
    if isinstance(eth_packet.data, dpkt.ip.IP):
        ip_packet = eth_packet.data
        src_addr = inet_to_str(ip_packet.src)
        dest_addr = inet_to_str(ip_packet.dst)

        if isinstance(ip_packet.data, dpkt.udp.UDP):
            protocol = "UDP"
            UDP = ip_packet.data
            src_port = UDP.sport
            dest_port = UDP.dport
            
        elif isinstance(ip_packet.data, dpkt.tcp.TCP):
            protocol = "TCP"
            TCP = ip_packet.data
            src_port = TCP.sport
            dest_port = TCP.dport
        else:
            protocol = "IP"

        packet_header["direction"] = str(direction)
        packet_header["src_addr"] = str(src_addr)
        packet_header["dest_addr"] = str(dest_addr)
        packet_header["protocol"] = str(protocol)
        packet_header["src_port"] = str(src_port)
        packet_header["dest_port"] = str(dest_port)


        accept_or_reject(packet_header)

        
    else:
        print ('Non IP Packet type not supported %s\n' % (eth_packet.data.__class__.__name__))
        continue


    
interface_file.close()
