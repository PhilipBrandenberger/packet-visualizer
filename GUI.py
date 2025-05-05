import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.backends.backend_tkagg import NavigationToolbar2Tk
import matplotlib.patches as mpatches
import networkx as nx
import numpy as np
from collections import defaultdict


class GUI:
    def __init__(self,analyzer,root):
        self.analyzer = analyzer
        self.root = root
        self.root.title("Packet Visualizer")
        self.root.geometry("1200x800")

        # store data
        self.pcap_file = None
        self.packets_data = []
        self.working_graph = None
        self.pos = None
        self.selected_node = None
        self.G = None

        # different frams
        self.control_frame = ttk.Frame(root,padding="10")
        self.control_frame.pack(fill="x")

        self.main_frame = ttk.Frame(root,padding="10")
        self.main_frame.pack(fill="both",expand=True)

        #layout
        self.main_frame.columnconfigure(0, weight=3)
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.rowconfigure(0,weight=1) 

        #area for graph
        self.graph_frame = ttk.Frame(self.main_frame, padding="5")
        self.graph_frame.grid(row=0,column=0,sticky="nsew")

        #panels
        self.info_frame = ttk.Frame(self.main_frame, padding="5")
        self.info_frame.grid(row=0, column=1, sticky="nsew")

        self.create_controls()
        self.create_graph_area()
        self.create_info_panel()
    
    def create_controls(self):
        """genral functions for layout logic"""
        ttk.Button(self.control_frame,
                   text="open a .pcap file",
                   command=self.load_pcap
                   ).pack(side="left",padx=5)
        
        # options for layout
        self.layout_var = tk.StringVar(value="spring")
        ttk.Label(self.control_frame, text="Layout:").pack(side='left', padx=5)
        
        layouts = ["spring", "circular", "kamada_kawai", "spectral"]
        layout_menu = ttk.Combobox(self.control_frame, 
                                   textvariable=self.layout_var, 
                                   values=layouts, 
                                   width=12,
                                   )
        layout_menu.pack(side='left', padx=5)

        #size options
        self.node_size_var = tk.StringVar(value="degree")
        ttk.Label(self.control_frame,text="Node Size:").pack(side='left', padx=5)
        
        size_options = ["degree", "packets", "fixed"]
        size_menu = ttk.Combobox(self.control_frame, 
                                 textvariable=self.node_size_var, 
                                 values=size_options, 
                                 width=8,
                                 )
        size_menu.pack(side='left', padx=5)

        # width options
        self.edge_width_var = tk.StringVar(value="weight")
        ttk.Label(self.control_frame, text="Edge Width:").pack(side='left', padx=5)
        width_options = ["weight", "packet_size", "fixed"]
        width_menu = ttk.Combobox(self.control_frame, 
                                  textvariable=self.edge_width_var, 
                                  values=width_options, 
                                  width=10,
                                  )
        width_menu.pack(side='left', padx=5)

        # checkbox
        # label
        self.label_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.control_frame, 
                        text="Show Labels",
                        variable=self.label_var,
                        ).pack(side='left', padx=5)

        # legend 
        self.legend_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.control_frame, 
                        text="Show Legend",
                        variable=self.legend_var,
                        ).pack(side='left', padx=5)

        # button
        ttk.Button(self.control_frame, 
                   text="refresh",
                   command=self.update_graph,
                   ).pack(side='left', padx=15)
        
        # options
        ttk.Separator(self.control_frame, orient='vertical').pack(side='left', padx=10, fill='y')
        
        self.enable_clustering_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(self.control_frame, 
                        text="Enable Clusters", 
                        variable=self.enable_clustering_var
                        ).pack(side='left', padx=5)
        # silder
        ttk.Label(self.control_frame, text="Threshold:").pack(side='left')
        self.cluster_threshold_var = tk.DoubleVar(value=0.1)
        threshold_scale = ttk.Scale(self.control_frame, 
                                    from_=0.01, 
                                    to=0.5, 
                                    variable=self.cluster_threshold_var, 
                                    orient=tk.HORIZONTAL, length=100,
                                    )
        threshold_scale.pack(side='left', padx=5)
    
    def create_graph_area(self):
        "creats the area for graphing"
        self.figure, self.ax = plt.subplots(figsize=(8, 6)) 
        self.canvas = FigureCanvasTkAgg(self.figure, master=self.graph_frame)
        self.canvas.get_tk_widget().pack(fill='both', expand=True)

        # toolbar
        self.toolbar = NavigationToolbar2Tk(self.canvas, self.graph_frame)
        self.toolbar.update()
        self.canvas.get_tk_widget().pack(fill="both", expand=True)

        # connect events
        self.canvas.mpl_connect("button_press_event", self.on_graph_click)

    def create_info_panel(self):
        """creats the info pannel areea """
        # Node info
        ttk.Label(self.info_frame, 
                  text="Node Information",
                  font=('TkDefaultFont', 12, 'bold'),
                  ).pack(fill='x')

        self.node_info = tk.Text(self.info_frame, 
                                 wrap=tk.WORD, 
                                 height=8,
                                 width=40,
                                 )
        self.node_info.pack(fill='both', expand=True, pady=5)

        # traffic details
        ttk.Label(self.info_frame, 
                  text="Traffic Details", 
                  font=('TkDefaultFont', 12, 'bold'),
                  ).pack(fill='x', pady=(10, 0))

        self.traffic_info = tk.Text(self.info_frame, 
                                    wrap=tk.WORD, 
                                    height=8, 
                                    width=40,)
        self.traffic_info.pack(fill='both', expand=True, pady=5)

        # payload 
        ttk.Label(self.info_frame,
                  text="Packet Payload",
                  font=('TkDefaultFont', 12, 'bold'),
                  ).pack(fill="x", pady=(10,0))
        self.payload_controls = ttk.Frame(self.info_frame)
        self.payload_controls.pack(fill="x",pady=2)
        
        # packet select
        ttk.Label(self.payload_controls, text="Packet ID:").pack(side='left', padx=5)
        self.packet_id_var = tk.StringVar()
        self.packet_dropdown = ttk.Combobox(self.payload_controls, 
                                            textvariable=self.packet_id_var,
                                            width=10,
                                            state='readonly'
                                            )
        self.packet_dropdown.pack(side='left', padx=5)
        self.packet_dropdown.bind('<<ComboboxSelected>>', self.update_payload_view)
        
        # view 
        ttk.Label(self.payload_controls, text="View:").pack(side='left', padx=5)
        self.payload_view_var = tk.StringVar(value="Hex")
        view_options = ttk.Combobox(self.payload_controls, 
                                    textvariable=self.payload_view_var,
                                    values=["Hex", "ASCII", "Both"],
                                    width=8,
                                    state='readonly'
                                    )
        view_options.pack(side='left', padx=5)
        view_options.bind('<<ComboboxSelected>>', self.update_payload_view)

        # payload text area scrollbar
        payload_frame = ttk.Frame(self.info_frame)
        payload_frame.pack(fill='both', expand=True, pady=2)
        
        payload_scroll = ttk.Scrollbar(payload_frame)
        payload_scroll.pack(side='right', fill='y')
        
        self.payload_text = tk.Text(payload_frame, 
                                    wrap=tk.WORD, 
                                    height=8,
                                    width=40,
                                    font=('Courier', 10),
                                    yscrollcommand=payload_scroll.set)
        self.payload_text.pack(fill='both', expand=True)
        payload_scroll.config(command=self.payload_text.yview)

        # stats
        ttk.Label(self.info_frame, 
                  text="pcap Statistics", 
                  font=('TkDefaultFont', 12, 'bold'),
                  ).pack(fill='x', pady=(10, 0))

        self.stats_info = tk.Text(self.info_frame, 
                                  wrap=tk.WORD, 
                                  height=6, 
                                  width=40,)
        self.stats_info.pack(fill='both', expand=True, pady=5)
    
    def load_pcap(self):
        """loads the contents of the pcap file"""

        filepath = filedialog.askopenfilename(title="Select PCAP file",
                                              filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")]
                                              )

        if not filepath:
            return

        self.pcap_file = filepath
        self.root.title(f"Packet Visualizer - {filepath}")

        try:
            # Show loading indicator
            self.root.config(cursor="watch")
            self.root.update()

            # processes the data
            self.G, self.packets_data = self.analyzer.process_pcap(filepath)

            if not self.packets_data:
                messagebox.showwarning("No Data", "No valid IP packets found in the PCAP file.")
                self.root.config(cursor="")
                return

            #  visualization
            self.update_graph()

            # statistics
            self.update_statistics()

            self.root.config(cursor="")
        
        except Exception as e:
            self.root.config(cursor="")
            messagebox.showerror("Error", f"Failed to process PCAP file: {str(e)}")
    
    def update_graph(self):
        """Updates the graph visualization with current settings"""
        if not self.G:
            return

        layout = self.layout_var.get()
        node_size_by = self.node_size_var.get()
        edge_width_by = self.edge_width_var.get()
        show_labels = self.label_var.get()
        show_legend = self.legend_var.get()
        
        #clustering is enabled
        if self.enable_clustering_var.get():

            clustered_graph = self.analyzer.cluster_nodes(self.G, self.cluster_threshold_var.get())
            self.working_graph = clustered_graph
        else:
            self.working_graph = self.G

        self.ax.clear()

        # layouts types
        if layout == "spring":
            self.pos = nx.spring_layout(self.working_graph, k=1.5, iterations=100)
        elif layout == "circular":
            self.pos = nx.circular_layout(self.working_graph)
        elif layout == "kamada_kawai":
            self.pos = nx.kamada_kawai_layout(self.working_graph)
        elif layout == "spectral":
            self.pos = nx.spectral_layout(self.working_graph)

        # nodes 
        node_colors = []
        node_sizes = []
        
        for node in self.working_graph.nodes():
            if self.working_graph.nodes[node].get("type") == "cluster":
                node_colors.append("purple")  
            elif self.working_graph.nodes[node].get("is_server", False):
                node_colors.append("red")     
            else:
                node_colors.append("blue")   
                
            #  node size
            if self.working_graph.nodes[node].get("type") == "cluster":
                cluster_size = self.working_graph.nodes[node].get("cluster_size", 1)
                node_sizes.append(500 * (1 + min(cluster_size, 10) * 0.3))
            elif node_size_by == "degree":
                node_sizes.append(300 * (1 + self.working_graph.degree(node)))
            elif node_size_by == "packets":
                node_sizes.append(300 * (1 + self.working_graph.nodes[node].get("packet_sent", 0) + self.working_graph.nodes[node].get("packet_received", 0)))
            else:
                node_sizes.append(700)

        # draws nodes
        nx.draw_networkx_nodes(self.working_graph,
                               self.pos,
                               node_size=node_sizes,
                               node_color=node_colors,
                               alpha=0.8,
                               edgecolors="black",
                               ax=self.ax
                               )

        # color mapping for prtocols
        protocol_colors = {
            "TCP": "blue",
            "UDP": "green",
            "ICMP": "red",
            "ARP": "orange",
            "DNS": "purple",
            "HTTP": "teal",
            "HTTPS": "#16a085",
            "SMTP": "yellow",
            "FTP": "darkorange",
            "SSH": "darkviolet",
            "UNKNOWN": "gray"
        }

        
        legend_elements = []
        for protocol, color in protocol_colors.items():
            edges_of_protocol = [(u, v) for u, v, d in self.working_graph.edges(data=True) if protocol in d.get("protocols", {})]

            # using numpy log to find the edfe width
            if edges_of_protocol:
                if edge_width_by == "weight":
                    edge_widths = [np.log(1 + self.working_graph[u][v]["weight"]) for u, v in edges_of_protocol]
                elif edge_width_by == "packet_size":
                    edge_widths = [np.log(1 + sum(self.working_graph[u][v].get('packet_sizes', [0]))) / 100 for u, v in edges_of_protocol]
                else:  
                    edge_widths = [1.5] * len(edges_of_protocol)
                 
                # color edges
                nx.draw_networkx_edges(
                    self.working_graph,
                    self.pos,
                    edgelist=edges_of_protocol,
                    width=edge_widths,
                    edge_color=color,
                    alpha=0.7,
                    ax=self.ax,
                )

                legend_elements.append(mpatches.Patch(color=color, label=protocol))

        if show_legend:
            if any(self.working_graph.nodes[n].get("is_server", False) for n in self.working_graph.nodes()):
                legend_elements.append(mpatches.Patch(color="red", label="Server"))
                legend_elements.append(mpatches.Patch(color="blue", label="Client"))
            
            if any(self.working_graph.nodes[n].get("type") == "cluster" for n in self.working_graph.nodes()):
                legend_elements.append(mpatches.Patch(color="purple", label="Node Cluster"))

        if show_labels:
            labels = {}
            for node in self.working_graph.nodes():
                if self.working_graph.nodes[node].get("type") == "cluster":
                    labels[node] = node  
                else:
                    labels[node] = f"{node}"
                    
            nx.draw_networkx_labels(
                self.working_graph,
                self.pos,
                labels=labels,
                font_size=8,
                font_weight='bold',
                bbox=dict(facecolor='white', edgecolor='none',alpha=0.7, boxstyle='round,pad=0.1'),
                ax=self.ax,
            )

        # legend can be enabled and disabled
        if show_legend and legend_elements:
            self.ax.legend(handles=legend_elements, loc="upper right")

        self.ax.axis("off")
        self.figure.tight_layout()
        self.canvas.draw()
    
    def on_graph_click(self, event):
        """when you click on the graph"""
        
        #clicks outside  graph area
        if event.xdata is None or event.ydata is None:
            return

        clicked_node = None
        min_distance = float('inf')

        for node, (x, y) in self.pos.items():
            dx = event.xdata - x
            dy = event.ydata - y
            distance = dx * dx + dy * dy

            if distance < min_distance and distance < 0.02:  
                clicked_node = node
                min_distance = distance

        if clicked_node:
            self.selected_node = clicked_node
            self.display_node_info(clicked_node)
            self.highlight_node(clicked_node)
    
    def highlight_node(self, node):
        """Highlight the selected node in the graph without redrawing entire graph"""
        
        # Don't call update_graph() here, which recalculates layouts and causes jumping
        # Just use the current graph state
        
        # Clear any previous highlights first (optional)
        self.ax.clear()
        
        # Get working graph
        working_graph = self.working_graph if hasattr(self, 'working_graph') and self.working_graph else self.G
        
        # Redraw with current positions, not recalculating layout
        # Draw normal nodes first
        all_nodes = list(working_graph.nodes())
        highlight_nodes = [node]
        normal_nodes = [n for n in all_nodes if n != node]
        
        # Get node sizes and colors as in update_graph
        node_colors = []
        node_sizes = []
        
        for n in normal_nodes:
            if working_graph.nodes[n].get("type") == "cluster":
                node_colors.append("purple")  
            elif working_graph.nodes[n].get("is_server", False):
                node_colors.append("red")     
            else:
                node_colors.append("blue")   
                
            #  node size
            if working_graph.nodes[n].get("type") == "cluster":
                cluster_size = working_graph.nodes[n].get("cluster_size", 1)
                node_sizes.append(500 * (1 + min(cluster_size, 10) * 0.3))
            elif self.node_size_var.get() == "degree":
                node_sizes.append(300 * (1 + working_graph.degree(n)))
            elif self.node_size_var.get() == "packets":
                node_sizes.append(300 * (1 + working_graph.nodes[n].get("packet_sent", 0) + working_graph.nodes[n].get("packet_received", 0)))
            else:
                node_sizes.append(700)
        
        # Draw normal nodes
        nx.draw_networkx_nodes(
            working_graph,
            self.pos,
            nodelist=normal_nodes,
            node_size=node_sizes,
            node_color=node_colors,
            alpha=0.8,
            edgecolors="black",
            ax=self.ax
        )
        
        # Draw edges
        edge_width_by = self.edge_width_var.get()
        protocol_colors = {
            "TCP": "blue",
            "UDP": "green",
            "ICMP": "red",
            "ARP": "orange",
            "DNS": "purple",
            "HTTP": "teal",
            "HTTPS": "#16a085",
            "SMTP": "yellow",
            "FTP": "darkorange",
            "SSH": "darkviolet",
            "UNKNOWN": "gray"
        }
        
        # Draw all edges with their protocol colors, similar to update_graph
        for protocol, color in protocol_colors.items():
            edges_of_protocol = [(u, v) for u, v, d in working_graph.edges(data=True) if protocol in d.get("protocols", {})]
            
            if edges_of_protocol:
                if edge_width_by == "weight":
                    edge_widths = [np.log(1 + working_graph[u][v]["weight"]) for u, v in edges_of_protocol]
                elif edge_width_by == "packet_size":
                    edge_widths = [np.log(1 + sum(working_graph[u][v].get('packet_sizes', [0]))) / 100 for u, v in edges_of_protocol]
                else:  
                    edge_widths = [1.5] * len(edges_of_protocol)
                    
                nx.draw_networkx_edges(
                    working_graph,
                    self.pos,
                    edgelist=edges_of_protocol,
                    width=edge_widths,
                    edge_color=color,
                    alpha=0.7,
                    ax=self.ax,
                )
        
        # Draw highlighted node on top
        nx.draw_networkx_nodes(
            working_graph,
            self.pos,
            nodelist=[node],
            node_size=700,
            node_color='yellow',
            edgecolors='black',
            linewidths=2,
            ax=self.ax
        )
        
        # Highlight connected edges
        connected_edges = list(working_graph.edges(node))
        if connected_edges:
            nx.draw_networkx_edges(
                working_graph,
                self.pos,
                edgelist=connected_edges,
                width=2,
                edge_color='yellow',
                alpha=1.0,
                ax=self.ax
            )
        
        # Add labels if enabled
        if self.label_var.get():
            labels = {}
            for n in working_graph.nodes():
                if working_graph.nodes[n].get("type") == "cluster":
                    labels[n] = n  
                else:
                    labels[n] = f"{n}"
                    
            nx.draw_networkx_labels(
                working_graph,
                self.pos,
                labels=labels,
                font_size=8,
                font_weight='bold',
                bbox=dict(facecolor='white', edgecolor='none', alpha=0.7, boxstyle='round,pad=0.1'),
                ax=self.ax,
            )
        
        # Restore legend if needed
        if self.legend_var.get():
            legend_elements = []
            for protocol, color in protocol_colors.items():
                if any(protocol in d.get("protocols", {}) for _, _, d in working_graph.edges(data=True)):
                    legend_elements.append(mpatches.Patch(color=color, label=protocol))
                    
            if any(working_graph.nodes[n].get("is_server", False) for n in working_graph.nodes()):
                legend_elements.append(mpatches.Patch(color="red", label="Server"))
                legend_elements.append(mpatches.Patch(color="blue", label="Client"))
            
            if any(working_graph.nodes[n].get("type") == "cluster" for n in working_graph.nodes()):
                legend_elements.append(mpatches.Patch(color="purple", label="Node Cluster"))
                
            if legend_elements:
                self.ax.legend(handles=legend_elements, loc="upper right")
        
        self.ax.axis("off")
        self.figure.tight_layout()
        self.canvas.draw()

    def display_node_info(self, node):
        """shows info about the selected node"""

        working_graph = self.working_graph if hasattr(self, 'working_graph') and self.working_graph else self.G
        node_data = working_graph.nodes[node]

        self.node_info.delete(1.0, tk.END)
        self.traffic_info.delete(1.0, tk.END)
        self.payload_text.delete(1.0, tk.END)


        if node_data.get("type") == "cluster":
            info = f"Cluster: {node}\n"
            info += f"Nodes in cluster: {node_data.get('cluster_size', 0)}\n"
            info += f"ips: {', '.join(node_data.get('cluster_ips', []))}\n"
            info += f"Packets Sent: {node_data.get('packet_sent', 0)}\n"
            info += f"Packets Received: {node_data.get('packet_received', 0)}\n"
            info += f"Protocols: {', '.join(sorted(node_data.get('protocols', [])))}\n"
            info += f"Contains Servers: {node_data.get('is_server', False)}\n\n"
        
            # individual nodes
            info += "Individual nodes in cluster:\n"
            for i, original_node in enumerate(node_data.get("original_nodes", [])):
                info += f"  {i+1}. {original_node}\n"
        else:
            info = f"Node: {node}\n"
            info += f"Type: {node_data.get('type', 'N/A')}\n"
            info += f"ip: {node_data.get('ip', 'N/A')}\n" if node_data.get('ip') else ""
            info += f"MAC: {node_data.get('mac', 'N/A')}\n" if node_data.get('mac') else ""
            info += f"Packets Sent: {node_data.get('packet_sent', 0)}\n"
            info += f"Packets Received: {node_data.get('packet_received', 0)}\n"
            info += f"Protocols: {', '.join(sorted(node_data.get('protocols', [])))}\n"
            info += f"Server: {node_data.get('is_server', False)}"

        self.node_info.insert(tk.END, info)


        
        connections = node_data.get("connections", [])
        traffic_info = "Connections:\n"
        for conn in connections:
            target = conn.get("target", "unknown")
            protocol = conn.get("protocol", "N/A")
            packets = conn.get("packet_count", 0)
            size = conn.get("total_bytes", 0)
            traffic_info += f"→ {target} | Protocol: {protocol} | Packets: {packets} | Size: {size} bytes\n"

        self.traffic_info.insert(tk.END, traffic_info)

        packet_ids = []
    
        # Check outgoing edges
        for edge_data in working_graph.edges(node, data=True):
            _, _, data = edge_data
            if "payloads" in data:
                for payload in data["payloads"]:
                    packet_ids.append(str(payload.get("packet_id")))
        
        # Check incoming edges 
        for edge_data in working_graph.in_edges(node, data=True):
            _, _, data = edge_data
            if "payloads" in data:
                for payload in data["payloads"]:
                    packet_ids.append(str(payload.get("packet_id")))
        
        # Update the dropdown
        if packet_ids:
            self.packet_dropdown['values'] = packet_ids
            self.packet_dropdown.current(0)
            self.update_payload_view()
        else:
            self.packet_dropdown['values'] = []
            self.packet_id_var.set("")
            self.payload_text.insert(tk.END, "No payload data available for this node")
    
    def update_payload_view(self, event=None):
        """Updates the payload view when packet ID or view type changes"""
        # Get the selected node and packet ID
        if not hasattr(self, 'selected_node') or not self.selected_node:
            return
            
        packet_id = self.packet_id_var.get()
        if not packet_id:
            return
            
        try:
            packet_id = int(packet_id)
        except ValueError:
            return
            
        # Find the payload data
        working_graph = self.working_graph if hasattr(self, 'working_graph') and self.working_graph else self.G
        
        # Clear the text area
        self.payload_text.delete(1.0, tk.END)
        
        payload_found = False
        
        # Check outgoing connections
        for edge in working_graph.edges(self.selected_node, data=True):
            src, dst, edge_data = edge
            if "payloads" in edge_data:
                for payload in edge_data["payloads"]:
                    if payload.get("packet_id") == packet_id:
                        view_type = self.payload_view_var.get()
                        self._display_payload(payload, view_type)
                        payload_found = True
                        break
            if payload_found:
                break
        
        # If not found in outgoing, check incoming
        if not payload_found:
            for src, dst, edge_data in working_graph.in_edges(self.selected_node, data=True):
                if "payloads" in edge_data:
                    for payload in edge_data["payloads"]:
                        if payload.get("packet_id") == packet_id:
                            view_type = self.payload_view_var.get()
                            self._display_payload(payload, view_type)
                            break

    def _display_payload(self, payload_data, view_type):
        """Displays payload data in specified format"""
        self.payload_text.delete(1.0, tk.END)
        
        if not payload_data:
            self.payload_text.insert(tk.END, "No payload data available")
            return
            
        # Add metadata
        metadata = f"Packet ID: {payload_data.get('packet_id')}\n"
        metadata += f"Protocol: {payload_data.get('protocol')}\n"
        metadata += f"Size: {payload_data.get('size')} bytes\n"
        metadata += f"Timestamp: {payload_data.get('timestamp')}\n"
        metadata += "-" * 40 + "\n\n"
        
        self.payload_text.insert(tk.END, metadata)
        
        # Format based on view type
        if view_type == "Hex" or view_type == "Both":
            hex_data = payload_data.get("hex", "")
            if hex_data:
                # Format hex data in groups of 2 chars with spaces
                formatted_hex = ""
                for i in range(0, len(hex_data), 2):
                    formatted_hex += hex_data[i:i+2] + " "
                    # Add line break every 16 bytes (32 hex chars)
                    if (i+2) % 32 == 0:
                        formatted_hex += "\n"
                
                self.payload_text.insert(tk.END, "HEX VIEW:\n")
                self.payload_text.insert(tk.END, formatted_hex + "\n\n")
                
        if view_type == "ASCII" or view_type == "Both":
            ascii_data = payload_data.get("ascii", "")
            if ascii_data:
                self.payload_text.insert(tk.END, "ASCII VIEW:\n")
                self.payload_text.insert(tk.END, ascii_data)
                
        if not payload_data.get("hex") and not payload_data.get("ascii"):
            self.payload_text.insert(tk.END, "No payload content available")


    def update_statistics(self):
        """updates info pannel stats"""
        if not self.packets_data:
            return

        self.stats_info.delete(1.0, tk.END)

        # basic stats
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

        # stats
        avg_size = sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0
        max_size = max(packet_sizes) if packet_sizes else 0
        min_size = min(packet_sizes) if packet_sizes else 0

        # show stats
        stats = f"Total Packets: {total_packets}\n"
        stats += f"Unique IP Addresses: {len(unique_ips)}\n"
        stats += f"Average Packet Size: {avg_size:.2f} bytes\n"
        stats += f"Min/Max Packet Size: {min_size}/{max_size} bytes\n\n"

        #protocol distribution
        stats += "Protocol Distribution:\n"
        for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_packets) * 100
            stats += f"  - {proto}: {count} ({percentage:.1f}%)\n"

        self.stats_info.insert(tk.END, stats)

