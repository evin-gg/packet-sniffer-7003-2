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
        determine_header_ipv4(payload)

    elif ether_type == "86DD":  # IPv6
        return
    else:
        print(f"  {'Unknown EtherType:':<25} {ether_type:<20} | {int(ether_type, 16)}")
        print("  No parser available for this EtherType.")

    return ether_type, payload

def determine_header_ipv4(hex_data):
    print(hex_data[18:20])
    if int(hex_data[18:20], 16) == 0x11:
        parse_udp_header(hex_data)
    elif int(hex_data[18:20], 16) == 0x06:
        parse_tcp_header(hex_data)
    elif int(hex_data[18:20], 16) == 0x01:
        parse_icmp_header(hex_data)



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

def parse_udp_header(hex_data):
    return

def parse_tcp_header(hex_data):
    #TODO
    return

def parse_icmp_header(hex_data):
    #TODO
    return