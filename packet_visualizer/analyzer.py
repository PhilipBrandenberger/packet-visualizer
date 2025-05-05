import networkx as nx
import scapy.all as sc
from collections import defaultdict
import numpy as np


class packet_analyzer:
    def __init__(self):
        self.packets_data = []
        self.G = None
    
    def extract_packets(self, pcap_file):
            """extract packet info from a .pcap"""

            packets = sc.rdpcap(pcap_file)
            data = []
            protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"} #

            for id, packet in enumerate(packets):
                # Using a dict because I wanted it raw data form and there would be too many objecst in memory 
                packet_info = {
                    "id": id,
                    "timestamp": getattr(packet, "time", None),
                    "src_mac": packet.src if hasattr(packet, 'src') else None,
                    "dst_mac": packet.dst if hasattr(packet, 'dst') else None,
                    "src_ip": None,
                    "dst_ip": None,
                    "protocol": None,
                    "ip_version": None,
                    "src_port": None,
                    "dst_port": None,
                    "flags": None,
                    "seq": None,
                    "ack": None,
                    "domain": None,
                    "packet_size": len(packet),
                    "ttl": None,
                    "service": None,
                    "error": None,
                    "payload": None,
                    "payload_hex": None,
                    "payload_ascii": None,
                }

                # Sorts based on the packet types
                try:
                    # mac
                    if sc.Ether in packet:
                        packet_info["src_mac"] = packet[sc.Ether].src
                        packet_info["dst_mac"] = packet[sc.Ether].dst
                    # arp
                    if sc.ARP in packet:
                        packet_info["src_ip"] = packet[sc.ARP].psrc
                        packet_info["dst_ip"] = packet[sc.ARP].pdst
                        packet_info["protocol"] = "ARP"
                        packet_info["ip_version"] = "ARP"
                        
                    # ipv4
                    elif sc.IP in packet:
                        ip = packet[sc.IP]
                        packet_info["src_ip"] = ip.src
                        packet_info["dst_ip"] = ip.dst
                        packet_info["protocol"] = protocol_map.get(ip.proto, f"Unknown({ip.proto})")
                        packet_info["ip_version"] = "IPv4"
                        packet_info["ttl"] = ip.ttl

                    # ipv6
                    elif sc.IPv6 in packet:
                        ip = packet[sc.IPv6]
                        packet_info["src_ip"] = ip.src
                        packet_info["dst_ip"] = ip.dst
                        packet_info["protocol"] = str(ip.nh)
                        packet_info["ip_version"] = "IPv6"
                        packet_info["ttl"] = ip.hlim

                    # tcp
                    if sc.TCP in packet:
                        tcp = packet[sc.TCP]
                        packet_info.update({
                            "src_port": tcp.sport,
                            "dst_port": tcp.dport,
                            "flags": str(tcp.flags),
                            "seq": tcp.seq,
                            "ack": tcp.ack,
                            "protocol": "TCP"
                        })

                        if hasattr(tcp,"payload") and len(tcp.payload) > 0:
                            payload_raw = bytes(tcp.payload)
                            packet_info["payload"] = payload_raw
                            packet_info["payload_hex"] = payload_raw.hex()
                            packet_info["payload_ascii"] = ''.join(chr(b) if 32 <= b < 127 else '.' for b in payload_raw)

                        # port to servers check
                        if tcp.sport == 80 or tcp.dport == 80:
                            packet_info["service"] = "HTTP"
                            packet_info["protocol"] = "HTTP"

                            #payload info
                            if hasattr(packet, 'load'):
                                try:
                                    payload_raw = bytes(packet.load)
                                    packet_info["payload"] = payload_raw
                                    packet_info["payload_hex"] = payload_raw.hex()
                                    packet_info["payload_ascii"] = ''.join(chr(b) if 32 <= b < 127 else '.' for b in payload_raw)
                                except:
                                    pass

                        elif tcp.sport == 443 or tcp.dport == 443:
                            packet_info["service"] = "HTTPS"
                            packet_info["protocol"] = "HTTPS"

                        elif tcp.sport == 22 or tcp.dport == 22:
                            packet_info["service"] = "SSH"
                            packet_info["protocol"] = "SSH"

                        elif tcp.sport == 21 or tcp.dport == 21:
                            packet_info["service"] = "FTP"
                            packet_info["protocol"] = "FTP"

                        elif tcp.sport == 25 or tcp.dport == 25:
                            packet_info["service"] = "SMTP"
                            packet_info["protocol"] = "SMTP"

                    # udp
                    elif sc.UDP in packet:
                        udp = packet[sc.UDP]
                        packet_info.update({
                            "src_port": udp.sport,
                            "dst_port": udp.dport,
                            "protocol": "UDP"
                        })

                        if hasattr(udp, 'payload') and len(udp.payload) > 0:
                            payload_raw = bytes(udp.payload)
                            packet_info["payload"] = payload_raw
                            packet_info["payload_hex"] = payload_raw.hex()
                            packet_info["payload_ascii"] = ''.join(chr(b) if 32 <= b < 127 else '.' for b in payload_raw)

                        if udp.sport == 53 or udp.dport == 53:
                            packet_info["service"] = "DNS"
                            packet_info["protocol"] = "DNS"

                    # dns
                    if sc.DNS in packet and packet[sc.DNS].qd is not None:
                        packet_info["protocol"] = "DNS"
                        packet_info["service"] = "DNS"
                        packet_info["domain"] = packet[sc.DNS].qd.qname.decode(
                            errors="ignore")

                    # icmp
                    if sc.ICMP in packet:
                        packet_info["protocol"] = "ICMP"
                        packet_info["service"] = "ICMP"
                    
                    if packet_info["payload"] is None and hasattr(packet, 'load'):
                        try:
                            payload_raw = bytes(packet.load)
                            packet_info["payload"] = payload_raw
                            packet_info["payload_hex"] = payload_raw.hex()
                            packet_info["payload_ascii"] = ''.join(chr(b) if 32 <= b < 127 else '.' for b in payload_raw)   
                        except:
                            pass
                except Exception as e:
                    packet_info["error"] = str(e)

                # Only add if we have valid source and destination information
                if packet_info["src_ip"] or packet_info["dst_ip"] or packet_info["src_mac"]:
                    data.append(packet_info)

            return data
    
    def build_graph(self,data):
        """builds a graph from packet data"""
        
        G = nx.DiGraph()  

        # Tracking traffic stats 
        traffic = defaultdict(int)
        protocols = defaultdict(set)

        # Node properties
        node_packet_sent = defaultdict(int)
        node_packet_rec = defaultdict(int)
        node_protocols = defaultdict(set)

        for packet in data:
            src = packet["src_ip"] if packet["src_ip"] else packet["src_mac"]
            dst = packet["dst_ip"] if packet["dst_ip"] else packet["dst_mac"]

            if src and dst:
                edge = (src, dst)
                protocol = packet["protocol"] or "UNKNOWN"

                # Update stats
                traffic[edge] += 1
                protocols[edge].add(protocol)

                # Node update
                node_packet_sent[src] += 1
                node_packet_rec[dst] += 1
                node_protocols[src].add(protocol)
                node_protocols[dst].add(protocol)

                # Add nodes 
                if not G.has_node(src):
                    G.add_node(
                        src,
                        type="IP" if packet["src_ip"] else "MAC",
                        packet_sent=0,
                        packet_received=0,
                        protocols=set(),
                        is_server=False,
                        mac=packet["src_mac"],
                        ip=packet["src_ip"],
                        connections=[],
                    )

                if not G.has_node(dst):
                    G.add_node(
                        dst,
                        type="IP" if packet["dst_ip"] else "MAC",
                        packet_sent=0,
                        packet_received=0,
                        protocols=set(),
                        is_server=False,
                        mac=packet["dst_mac"],
                        ip=packet["dst_ip"],
                        connections=[],
                    )

                #update properties
                G.nodes[src]["packet_sent"] += 1
                G.nodes[dst]["packet_received"] += 1
                G.nodes[src]["protocols"].add(protocol)
                G.nodes[dst]["protocols"].add(protocol)
                
                # Add connection info to node for detailed viewing
                connection_info = {
                    "target": dst,
                    "protocol": protocol,
                    "packet_count": 1,
                    "total_bytes": packet["packet_size"],
                    "timestamp": packet["timestamp"],
                    "packet_id": packet["id"],
                }
                
                # add/update connection 
                existing_conn = next((c for c in G.nodes[src].get("connections", []) if c["target"] == dst and c["protocol"] == protocol), None)
                if existing_conn:
                    existing_conn["packet_count"] += 1
                    existing_conn["total_bytes"] += packet["packet_size"]
                else:
                    if "connections" not in G.nodes[src]:
                        G.nodes[src]["connections"] = []
                    G.nodes[src]["connections"].append(connection_info)

                # add/update edge
                if G.has_edge(src, dst):
                    G[src][dst]["weight"] += 1
                    G[src][dst]["protocols"].add(protocol)

                    # size
                    if "packet_sizes" not in G[src][dst]:
                        G[src][dst]["packet_sizes"] = []
                    G[src][dst]["packet_sizes"].append(packet["packet_size"])

                    # ports
                    if "src_ports" not in G[src][dst]:
                        G[src][dst]["src_ports"] = set()
                    if "dst_ports" not in G[src][dst]:
                        G[src][dst]["dst_ports"] = set()

                    if packet.get("src_port"):
                        G[src][dst]["src_ports"].add(packet["src_port"])
                    if packet.get("dst_port"):
                        G[src][dst]["dst_ports"].add(packet["dst_port"])

                    if "packet_ids" not in G[src][dst]:
                        G[src][dst]["packet_ids"] = []
                    G[src][dst]["packet_ids"].append(packet["id"])
                    
                    # store payload  
                    if "payloads" not in G[src][dst]:
                        G[src][dst]["payloads"] = []
                    
                    if packet.get("payload") is not None:
                        payload_entry = {
                            "packet_id": packet["id"],
                            "hex": packet.get("payload_hex"),
                            "ascii": packet.get("payload_ascii"),
                            "protocol": protocol,
                            "timestamp": packet["timestamp"],
                            "size": len(packet.get("payload", b'')),
                        }
                        G[src][dst]["payloads"].append(payload_entry)
                else:
                    edge_data = {
                        "weight": 1,
                        "protocols": {protocol},
                        "packet_sizes": [packet["packet_size"]],
                        "src_ports": set([packet.get("src_port")]) if packet.get("src_port") else set(),
                        "dst_ports": set([packet.get("dst_port")]) if packet.get("dst_port") else set(),
                        "packet_ids": [packet["id"]],
                        "payloads": [],
                    }
                    
                    # payload if available
                    if packet.get("payload") is not None:
                        payload_entry = {
                            "packet_id": packet["id"],
                            "hex": packet.get("payload_hex"),
                            "ascii": packet.get("payload_ascii"),
                            "protocol": protocol,
                            "timestamp": packet["timestamp"],
                            "size": len(packet.get("payload", b''))
                        }
                        edge_data["payloads"].append(payload_entry)
                        
                    G.add_edge(src, dst, **edge_data)

        self.identify_servers(G)
        return G
    
    
    def identify_servers(self, G):
        """gusses what are servers based on traffic"""
        for node in G.nodes():
            
            
            incoming = sum(1 for u, v in G.edges() if v == node)
            outgoing = sum(1 for u, v in G.edges() if u == node)

            server_ports = {80, 443, 22, 21, 25, 53, 3306, 5432, 8080, 8443}
            has_server_port = False
            
            incoming_edges = [(u, node) for u, v in G.edges() if v == node]

            for edge in incoming_edges:
                u, v = edge
                if any(port in server_ports for port in G[u][v].get("dst_ports", set())):
                    has_server_port = True
                    break
            # known server ports/ over 50% more incoming traffic 
            if (incoming > outgoing * 1.5) or has_server_port:
                G.nodes[node]["is_server"] = True 
    
    def cluster_nodes(self, G, threshold=0.1):
        """Cluster nodes that are spatially close to each other"""

        temp_pos = nx.spring_layout(G, k=1.5, iterations=50)
        clusters = defaultdict(list)
        assigned = set()
        
        # important = degree + packet count
        nodes_by_importance = sorted(G.nodes(),
                                    key=lambda n: G.degree(n) + G.nodes[n].get("packet_sent", 0),
                                    reverse=True,
                                    )
        
        # Create clusters
        for node in nodes_by_importance:
            if node in assigned:
                continue

            id = len(clusters)
            clusters[id].append(node)
            assigned.add(node)
            

            for other_node in G.nodes():
                if other_node != node and other_node not in assigned:
                    # distance math
                    pos1 = temp_pos[node]
                    pos2 = temp_pos[other_node]
                    distance = ((pos1[0] - pos2[0])**2 + (pos1[1] - pos2[1])**2)**0.5
                    
                    if distance < threshold:
                        clusters[id].append(other_node)
                        assigned.add(other_node)
        
        CG = nx.Graph()
        
        # deals with both individual and cluster nodes
        for id, nodes in clusters.items():
            if len(nodes) == 1:
                node = nodes[0]
                CG.add_node(node, **G.nodes[node])
            else:
                node_ips = set()
                for node in nodes:
                    if G.nodes[node].get("ip"):
                        node_ips.add(G.nodes[node]["ip"])
                        
                cluster_data = {
                    "type": "cluster",
                    "cluster_size": len(nodes),
                    "cluster_ips": list(node_ips),
                    "packet_sent": sum(G.nodes[node].get("packet_sent", 0) for node in nodes),
                    "packet_received": sum(G.nodes[node].get("packet_received", 0) for node in nodes),
                    "protocols": set().union(*(G.nodes[node].get("protocols", set()) for node in nodes)),
                    "is_server": any(G.nodes[node].get("is_server", False) for node in nodes),
                    "original_nodes": nodes
                }
                
                cluster_label = f"Cluster ({len(nodes)} nodes)"
                CG.add_node(cluster_label, **cluster_data)
        
        
        #add the edges between nodes
        for u, v, data in G.edges(data=True):
                u_cluster = find_cluster(u,clusters)
                v_cluster = find_cluster(v,clusters)
                
                if u_cluster == v_cluster:
                    continue
                    
                u_rep = u if len(clusters[u_cluster]) == 1 else f"Cluster ({len(clusters[u_cluster])} nodes)"
                v_rep = v if len(clusters[v_cluster]) == 1 else f"Cluster ({len(clusters[v_cluster])} nodes)"
                
                # node update
                if CG.has_edge(u_rep, v_rep):
                    CG[u_rep][v_rep]["weight"] += data["weight"]
                    CG[u_rep][v_rep]["protocols"].update(data["protocols"])
                    
                    #comabine sizes and ids
                    if "packet_sizes" in data:
                        if "packet_sizes" not in CG[u_rep][v_rep]:
                            CG[u_rep][v_rep]["packet_sizes"] = []
                        CG[u_rep][v_rep]["packet_sizes"].extend(data["packet_sizes"])
                        
                    if "packet_ids" in data:
                        if "packet_ids" not in CG[u_rep][v_rep]:
                            CG[u_rep][v_rep]["packet_ids"] = []
                        CG[u_rep][v_rep]["packet_ids"].extend(data["packet_ids"])
                        
                    # comabine ports
                    if "src_ports" in data:
                        if "src_ports" not in CG[u_rep][v_rep]:
                            CG[u_rep][v_rep]["src_ports"] = set()
                        CG[u_rep][v_rep]["src_ports"].update(data["src_ports"])
                        
                    if "dst_ports" in data:
                        if "dst_ports" not in CG[u_rep][v_rep]:
                            CG[u_rep][v_rep]["dst_ports"] = set()
                        CG[u_rep][v_rep]["dst_ports"].update(data["dst_ports"])    
                else:
                    CG.add_edge(u_rep, v_rep, **data)        
        return CG
    
    def process_pcap(self, filepath):
        """returns a graph"""
        self.packets_data = self.extract_packets(filepath)
        
        # Sort packets by timestamp
        self.packets_data.sort(
            key=lambda x: x["timestamp"] if x["timestamp"] is not None else 0)
            
        # Build graph
        self.G = self.build_graph(self.packets_data)
        
        return self.G, self.packets_data

    def get_statistics(self):
        """Get statistics about the processed packets"""
        
        if not self.packets_data:
            return {}
            
        stats = {}
        total_packets = len(self.packets_data)
        unique_ips = set()
        protocols = defaultdict(int)
        packet_sizes = []

        for packet in self.packets_data:
            if packet["src_ip"]:
                unique_ips.add(packet["src_ip"])
            if packet["dst_ip"]:
                unique_ips.add(packet["dst_ip"])

            if packet["protocol"]:
                protocols[packet["protocol"]] += 1

            packet_sizes.append(packet["packet_size"])

        # calculate stats
        stats["total_packets"] = total_packets
        stats["unique_ips"] = len(unique_ips)
        stats["avg_size"] = sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0
        stats["max_size"] = max(packet_sizes) if packet_sizes else 0
        stats["min_size"] = min(packet_sizes) if packet_sizes else 0
        stats["protocols"] = dict(protocols)
        
        return stats


def find_cluster(node,clusters):
    """helper function to find node in cluster"""
    for cluster_id, cluster_nodes in clusters.items():
        if node in cluster_nodes:
            return cluster_id
    return None