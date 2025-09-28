# Parse Ethernet header
def parse_ethernet_header(hex_data):
    dest_mac = ':'.join(hex_data[i:i+2] for i in range(0, 12, 2))
    source_mac = ':'.join(hex_data[i:i+2] for i in range(12, 24, 2))
    ether_type = hex_data[24:28]

    print(f"Ethernet Header:")
    print(f"  {'Destination MAC:':<25} {hex_data[0:12]:<20} | {dest_mac}")
    print(f"  {'Source MAC:':<25} {hex_data[12:24]:<20} | {source_mac}")
    print(f"  {'EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")

    payload = hex_data[28:]

    # Route payload based on EtherType
    if ether_type == "0806":  # ARP
        parse_arp_header(payload)

    elif ether_type == "0800":  # IPv4
        parse_ipv4_header(payload)
        
    elif ether_type == "86dd":  # IPv6
        parse_ipv6_header(payload)
    else:
        print(f"  {'Unknown EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")
        print("  No parser available for this EtherType.")

    return ether_type, payload

def determine_header(protocol, hex_data):
    if protocol == 0x11:
        parse_udp_header(hex_data)
    elif protocol == 0x06:
        parse_tcp_header(hex_data)
    elif protocol == 0x01:
        parse_icmp_header(hex_data)
    elif protocol == 0x0:

        offset = int(hex_data[82:84], 16)

        if offset == 0x00:
            offset = 16

        parse_icmpv6_header(hex_data, offset)

    elif protocol == 0x3A:
        parse_icmpv6_header(hex_data, 0)


# Parse ARP header
def parse_arp_header(hex_data):
    hardware_type = int(hex_data[:4], 16)
    protocol_type = int(hex_data[4:8], 16)
    hardware_size = int(hex_data[8:10], 16)
    protocol_size = int(hex_data[10:12], 16)
    opcode = int(hex_data[12:16], 16)
    source_mac = int(hex_data[16:28], 16)
    source_ip = int(hex_data[28:36], 16)
    destination_mac = int(hex_data[36:48], 16)
    destination_ip = int(hex_data[48:56], 16)

    print(f"ARP Header:")
    print(f"  {'Hardware Type:':<25} {hex_data[:4]:<20} | {hardware_type}")
    print(f"  {'Protocol Type:':<25} {hex_data[4:8]:<20} | {protocol_type}")
    print(f"  {'Hardware Size:':<25} {hex_data[8:10]:<20} | {hardware_size}")
    print(f"  {'Protocol Size:':<25} {hex_data[10:12]:<20} | {protocol_size}")
    print(f"  {'Opcode:':<25} {hex_data[12:16]:<20} | {opcode}")
    print(f"  {'Source MAC:':<25} {hex_data[16:28]:<20} | {source_mac}")
    print(f"  {'Source IP Address':<25} {hex_data[28:36]:<20} | {source_ip}")
    print(f"  {'Destination MAC:':<25} {hex_data[36:48]:<20} | {destination_mac}")
    print(f"  {'Destination IP Address:':<25} {hex_data[48:56]:<20} | {destination_ip}")

def parse_ipv4_header(hex_data):
    for i in range(0, len(hex_data), 2):
        print(hex_data[i:i+2], end=' ')
    print()

    # Version and header length bits
    version_headerlen = int(hex_data[:2], 16)
    version = (version_headerlen >> 4) & 0xF
    header_len = version_headerlen & 0xF

    # Differentiated Services Field
    diff_serv_field = int(hex_data[2:4], 16)
    dscp = (diff_serv_field >> 2) & 0x3F
    ecn = diff_serv_field & 0x03

    # Total Length
    total_length = int(hex_data[4:8], 16)

    # Identification
    identification = int(hex_data[8:12], 16)

    # Flags and fragment offset
    flags_fragment = int(hex_data[12:16], 16)
    reserved_bit = (flags_fragment >> 15) & 0x1
    dont_fragment = (flags_fragment >> 14) & 0x1
    more_fragments = (flags_fragment >> 13) & 0x1
    fragment_offset = flags_fragment & 0x1FFF

    # Time to live
    time_to_live = int(hex_data[16:18], 16)
    
    # Protocol
    protocol = int(hex_data[18:20], 16)

    # Header checksum
    checksum = int(hex_data[20:24], 16)

    # Source address
    source_ip = int(hex_data[24:32], 16)

    # Destination address
    dest_ip = int(hex_data[32:40], 16)

    print(f"  {'Version:':<25} {version:<20} | {version}")
    print(f"  {'Header Length:':<25} {header_len:<20} | {header_len * 4} bytes")
    print(f"  {'Differentiated Services Field:':<25} {hex_data[2:4]:<20} | {diff_serv_field}")
    print(f"    {'DSCP:':<23} {dscp:06b}")
    print(f"    {'ECN:':<23} {ecn:02b}")
    print(f"  {'Total Length:':<25} {hex_data[4:8]:<20} | {total_length} bytes")
    print(f"  {'Identification:':<25} {hex_data[8:12]:<20} | {identification}")
    print(f"  {'Flags:':<25} {hex_data[12:16]:<20} | {flags_fragment:016b}")
    print(f"    {'Reserved Bit:':<23} {(reserved_bit):01b}")
    print(f"    {'Don\'t Fragment:':<23} {(dont_fragment):01b}")
    print(f"    {'More Fragments:':<23} {(more_fragments):01b}")
    print(f"    {'Fragment Offset:':<23} {fragment_offset:<20} | {fragment_offset} bytes")
    print(f"  {'Time to Live:':<25} {hex_data[16:18]:<20} | {time_to_live}")
    print(f"  {'Protocol:':<25} {hex_data[18:20]:<20} | {protocol}")
    print(f"  {'Checksum:':<25} {hex_data[20:24]:<20} | {checksum}")
    print(f"  {'Source Address:':<25} {hex_data[24:32]:<20} | {source_ip}")
    print(f"  {'Destination Address:':<25} {hex_data[32:40]:<20} | {dest_ip}")

    determine_header(protocol, hex_data)

def parse_ipv6_header(hex_data):
    ipv6_start = int(hex_data[0:8], 16)
    version = (ipv6_start >> 28) & 0xF
    traffic_class = (ipv6_start >> 20) & 0xFF
    differentiated_services = (ipv6_start >> 22) & 0x3F
    explicit_congestion = (ipv6_start >> 20) & 0x3
    flow_label = ipv6_start & 0xFFFFF

    payload_length = int(hex_data[8:12], 16)
    next_header = int(hex_data[12:14], 16)
    hop_limit = int(hex_data[14:16], 16)

    source_ip = int(hex_data[16:48], 16)
    dest_ip = int(hex_data[48:80], 16)

    print(f"IPv6 Header:")
    print(f"  {'Version:':<25} {version:<20} | {version}")
    print(f"  {'Traffic Class:':<25} {traffic_class:<20} | {traffic_class}")
    print(f"  {'Differentiated Services:':<25} {differentiated_services:<20} | {differentiated_services}")
    print(f"  {'Explicit Congestion Notification:':<25} {explicit_congestion:<20} | {explicit_congestion}")
    print(f"  {'Flow Label:':<25} {flow_label:<20} | {flow_label}")
    print(f"  {'Payload Length:':<25} {hex_data[8:12]:<20} | {payload_length} bytes")
    print(f"  {'Next Header:':<25} {hex_data[12:14]:<20} | {next_header}")
    print(f"  {'Hop Limit:':<25} {hex_data[14:16]:<20} | {hop_limit}")
    print(f"  {'Source Address:':<25} {hex_data[16:48]:<20} | {source_ip}")
    print(f"  {'Destination Address:':<25} {hex_data[48:80]:<20} | {dest_ip}")

    determine_header(next_header, hex_data)

def parse_udp_header(hex_data):
    source_port = int(hex_data[40:44], 16)
    dest_port = int(hex_data[44:48], 16)
    length = int(hex_data[48:52], 16)
    checksum = int(hex_data[52:56], 16)
    payload = hex_data[56:]

    print(f"UDP Header:")
    print(f"  {'Source Port:':<25} {hex_data[40:44]:<20} | {source_port}")
    print(f"  {'Destination Port:':<25} {hex_data[44:48]:<20} | {dest_port}")
    print(f"  {'Length:':<25} {hex_data[48:52]:<20} | {length}")
    print(f"  {'Checksum:':<25} {hex_data[52:56]:<20} | {checksum}")

    if source_port == 53 or dest_port == 53:
        parse_dns_header(hex_data)
    else:
        print(f"  {'Payload (hex):':<25} {payload if payload else 'None'}")

def parse_tcp_header(hex_data):
    source_port = int(hex_data[40:44], 16)
    dest_port = int(hex_data[44:48], 16)
    seq_number = int(hex_data[48:56], 16)
    ack_number = int(hex_data[56:64], 16)

    # entire headerlen + flags
    headerlen_flags = int(hex_data[64:68], 16)
    data_offset = (headerlen_flags >> 12) & 0xF
    reserved = (headerlen_flags >> 9) & 0x3

    # flags
    accurate_ecn = (headerlen_flags >> 8) & 0x1
    congestion_window = (headerlen_flags >> 7) & 0x1
    ecn_echo = (headerlen_flags >> 6) & 0x1
    urgent = (headerlen_flags >> 5) & 0x1
    ack = (headerlen_flags >> 4) & 0x1
    push = (headerlen_flags >> 3) & 0x1
    reset = (headerlen_flags >> 2) & 0x1
    syn = (headerlen_flags >> 1) & 0x1
    fin = (headerlen_flags >> 0) & 0x1

    window = int(hex_data[68:72], 16)
    checksum = int(hex_data[72:76], 16)
    urgent_pointer = int(hex_data[76:80], 16)

    options = int(hex_data[80:104], 16)
    payload = hex_data[104:]

    print(f"TCP Header:")
    print(f"  {'Source Port:':<25} {hex_data[40:44]:<20} | {source_port}")
    print(f"  {'Destination Port:':<25} {hex_data[44:48]:<20} | {dest_port}")
    print(f"  {'Sequence number:':<25} {hex_data[48:56]:<20} | {seq_number}")
    print(f"  {'Acknowledgement number:':<25} {hex_data[56:64]:<20} | {ack_number}")
    print(f"  {'Data Offset:':<25} {hex_data[64:68]:<20} | {data_offset * 4} bytes")
    print(f"  {'Reserved:':<25} {reserved:03b} | {reserved}")
    print(f"  {'Flags:':<25} {headerlen_flags & 0x1FF:09b}")
    print(f"    {'Accurate ECN:':<23} {accurate_ecn:01b}")
    print(f"    {'Congestion Window Reduced:':<23} {congestion_window:01b}")
    print(f"    {'ECN-Echo:':<23} {ecn_echo:01b}")
    print(f"    {'Urgent:':<23} {urgent:01b}")
    print(f"    {'Acknowledgement:':<23} {ack:01b}")
    print(f"    {'Push:':<23} {push:01b}")
    print(f"    {'Reset:':<23} {reset:01b}")
    print(f"    {'Syn:':<23} {syn:01b}")
    print(f"    {'Fin:':<23} {fin:01b}")
    print(f"  {'Window:':<25} {hex_data[68:72]:<20} | {window}")
    print(f"  {'Checksum:':<25} {hex_data[72:76]:<20} | {checksum}")
    print(f"  {'Urgent Pointer:':<25} {hex_data[76:80]:<20} | {urgent_pointer}")
    print(f"  {'Options:':<25} {hex_data[80:104]:<20} | {options}")

    if source_port == 53 or dest_port == 53:
        parse_dns_header(hex_data)
    else:
        print(f"  {'Payload (hex):':<25} {payload if payload else 'None'}")

def parse_icmp_header(hex_data):
    type = int(hex_data[40:42], 16)
    code = int(hex_data[42:44], 16)
    checksum = int(hex_data[44:48], 16)
    rest_of_header = int(hex_data[48:56], 16)
    payload = hex_data[56:]

    print(f"ICMP Header:")
    print(f"  {'Type:':<25} {hex_data[40:42]:<20} | {type}")
    print(f"  {'Code:':<25} {hex_data[42:44]:<20} | {code}")
    print(f"  {'Checksum:':<25} {hex_data[44:48]:<20} | {checksum}")
    print(f"  {'Rest of Header:':<25} {hex_data[48:56]:<20} | {rest_of_header}")
    print(f"  {'Payload (hex):':<25} {payload if payload else 'None'}")

def parse_dns_header(hex_data):
    print(f"DNS Header:")


    transaction_id = int(hex_data[104:108], 16)
    print(f"  {'Transaction ID:':<25} {hex_data[104:108]:<20} | {transaction_id}")


    # flags
    flags = int(hex_data[108:112], 16)
    response = (flags >> 15) & 0x1

    print(f"  {'Flags:':<25} {hex_data[108:112]:<20} | {flags:016b}")
    print(f"    {'Response:':<23} {response:01b} | {'Response' if response else 'Query'}")

    if(response == 0):
        query_dns(flags)

    elif (response == 1):
        response_dns(flags)


    questions = int(hex_data[112:116], 16)
    answer_rrs = int(hex_data[116:120], 16)
    authority_rrs = int(hex_data[120:124], 16)
    additional_rrs = int(hex_data[124:128], 16)

    print(f"  {'Questions:':<25} {hex_data[112:116]:<20} | {questions}")
    print(f"  {'Answer RRs:':<25} {hex_data[116:120]:<20} | {answer_rrs}")
    print(f"  {'Authority RRs:':<25} {hex_data[120:124]:<20} | {authority_rrs}")
    print(f"  {'Additional RRs:':<25} {hex_data[124:128]:<20} | {additional_rrs}")

def response_dns(flags):
    opcode = (flags >> 11) & 0xF
    authoritative = (flags >> 10) & 0x1
    truncated = (flags >> 9) & 0x1
    recursion_desired = (flags >> 8) & 0x1
    recursion_available = (flags >> 7) & 0x1
    z = (flags >> 6) & 0x1
    auth_data = (flags >> 5) & 0x1
    non_auth_data = (flags >> 4) & 0x1
    reply_code = flags & 0xF

    print(f"  {'Opcode:':<25} {opcode:04b}")
    print(f"  {'Authoritative:':<25} {authoritative:01b}")
    print(f"  {'Truncated:':<25} {truncated:01b}")
    print(f"  {'Recursion Desired:':<25} {recursion_desired:01b}")
    print(f"  {'Recursion Available:':<25} {recursion_available:01b}")
    print(f"  {'Z:':<25} {z:01b}")
    print(f"  {'Authenticated Data:':<25} {auth_data:01b}")
    print(f"  {'Non-authenticated Data:':<25} {non_auth_data:01b}")
    print(f"  {'Reply Code:':<25} {reply_code:04b}")

def query_dns(flags):
    opcode = (flags >> 11) & 0xF
    truncated = (flags >> 9) & 0x1
    recursion_desired = (flags >> 8) & 0x1
    z = (flags >> 6) & 0x1
    non_auth_data = (flags >> 4) & 0x1

    print(f"  {'Opcode:':<25} {opcode:04b}")
    print(f"  {'Truncated:':<25} {truncated:01b}")
    print(f"  {'Recursion Desired:':<25} {recursion_desired:01b}")
    print(f"  {'Z:':<25} {z:01b}")
    print(f"  {'Non-authenticated Data:':<25} {non_auth_data:01b}")

def parse_icmpv6_header(hex_data, offset):
    type = int(hex_data[80 + offset:82 + offset], 16)
    code = int(hex_data[82 + offset:84 + offset], 16)
    checksum = int(hex_data[84 + offset:88 + offset], 16)

    print(f"ICMPv6 Header:")
    print(f"  {'Type:':<25} {hex_data[80 + offset:82 + offset]:<20} | {type}")
    print(f"  {'Code:':<25} {hex_data[82 + offset:84 + offset]:<20} | {code}")
    print(f"  {'Checksum:':<25} {hex_data[84 + offset:88 + offset]:<20} | {checksum}")