from scapy.all import *


def detect_dga(packets):
    # A tester
    # https://cylab.be/blog/245/network-traffic-analysis-with-python-scapy-and-some-machine-learning
    counts = {}
    # QR = Query Response
    # ANCOUNT = Answer Count
    # https://datatracker.ietf.org/doc/html/rfc5395#section-2
    for packet in packets:
        if packet.haslayer(DNS) and packet[DNS].qr == 1 and packet[DNS].ancount == 0:
            # DNS query returned no answer
            # extract the destination IP (device that sent the query)
            ip = packet[IP].dst
            counts[ip] = counts.get(ip, 0) + 1

    threshold = 100  # faire varier le threshold

    print("+ Create list of suspicious IP addresses ...")
    suspicious = []
    for ip, occurrences in counts.items():
        if occurrences < threshold:
            continue
        suspicious.append(ip)
    print(suspicious)


def escape_label(label):
    # Escape characters that may cause syntax errors in DOT graph
    label = label.replace('"', r'\"')  # Escape double quotes
    # label = label.replace("'", r"\'")  # Escape single quotes
    return label


def get_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except socket.herror:
        return None  # If reverse DNS lookup fails, return IP address


def build_ip_dot_graph(pcap_file, output_file):
    # Read pcap file
    packets = rdpcap(pcap_file)

    # Initialize DOT graph
    dot_graph = "digraph pcap_communication {\n"

    # Track unique IP pairs to avoid duplicate edges
    ip_pairs = set()

    # Iterate through packets
    for pkt in packets:
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            # Ensure only unique IP pairs are added to the graph
            if (src_ip, dst_ip) not in ip_pairs:
                ip_pairs.add((src_ip, dst_ip))

                src_hostname = get_hostname(src_ip)
                dst_hostname = get_hostname(dst_ip)

                # Add nodes and edges to the DOT graph

                # TODO : add label like [label="ssh,telnet"] on edges for protocols

                # Print hostname if different from IP
                if src_hostname:
                    if dst_hostname:
                        dot_graph += f'"{src_ip} ({src_hostname})" -> "{dst_ip} ({src_hostname})";\n'
                    else:
                        dot_graph += f'"{src_ip} ({src_hostname})" -> "{dst_ip}";\n'
                elif dst_hostname:
                    dot_graph += f'"{src_ip}" -> "{dst_ip} ({dst_hostname})";\n'
                else:
                    dot_graph += f'"{src_ip}" -> "{dst_ip}";\n'

    dot_graph += "}"

    # Write DOT graph to output file
    with open(output_file, "w") as f:
        f.write(dot_graph)

    # Les flèches ont un sens sur les directions des flux
    print("DOT graph generated successfully.")


def get_dns_qry():
    ...


"""
packets = PcapReader('poisoned_credentials.pcap') # create a generator, does NOT load the complete file in mem
for packet in packets:
    # print(packet.show())

    if packet.haslayer(DNSQR):
        print(packet[DNSQR].qname.decode())
"""

# TESTS
if __name__ == '__main__':
    # Test the DGA detection function
    # detect_dga(packets)

    # Test the IP DOT graph building function
    build_ip_dot_graph("poisoned_credentials.pcap", "communication_graph.dot")
