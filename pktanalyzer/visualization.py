"""
PktAnalyzer Visualization Module

This module provides visualization functionality for packet analysis using matplotlib.
"""

from typing import List, Dict, Any, Optional, Tuple
import os

try:
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    from matplotlib.patches import Wedge
    import numpy as np
except ImportError:
    raise ImportError("Matplotlib and numpy are required. Install with: pip install matplotlib numpy")

try:
    from scapy.all import Packet
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import ARP, Ether
except ImportError:
    raise ImportError("Scapy is required. Install with: pip install scapy")

from datetime import datetime
from collections import Counter
from .utils import setup_logging, get_protocol_name, format_bytes


class PacketVisualizer:
    """
    Main visualization class for packet analysis.
    """
    
    def __init__(self, verbose: bool = False, style: str = 'default'):
        """
        Initialize packet visualizer.
        
        Args:
            verbose (bool): Enable verbose logging
            style (str): Matplotlib style to use
        """
        self.verbose = verbose
        self.logger = setup_logging(verbose)
        
        # Set matplotlib style
        try:
            plt.style.use(style)
        except:
            plt.style.use('default')
        
        # Configure matplotlib for better appearance
        plt.rcParams['figure.figsize'] = (10, 6)
        plt.rcParams['font.size'] = 10
        plt.rcParams['axes.grid'] = True
        plt.rcParams['grid.alpha'] = 0.3
    
    def plot_protocol_distribution(self, packets: List[Any], 
                                 save_path: Optional[str] = None,
                                 show_percentages: bool = True,
                                 max_protocols: int = 10) -> None:
        """
        Create a pie chart of protocol distribution.
        
        Args:
            packets (List): Packets to analyze
            save_path (str, optional): Path to save the plot
            show_percentages (bool): Show percentages on the chart
            max_protocols (int): Maximum number of protocols to show
        
        Examples:
            >>> plot_protocol_distribution(packets, "protocol_dist.png")
        """
        if not packets:
            self.logger.warning("No packets to visualize")
            return
        
        # Count protocols
        protocol_counts = Counter()
        for packet in packets:
            protocol_counts[get_protocol_name(packet)] += 1
        
        # Get top protocols
        top_protocols = protocol_counts.most_common(max_protocols)
        
        if len(protocol_counts) > max_protocols:
            # Group remaining protocols as "Others"
            others_count = sum(count for _, count in protocol_counts.most_common()[max_protocols:])
            top_protocols.append(("Others", others_count))
        
        # Prepare data for plotting
        labels = [proto for proto, _ in top_protocols]
        sizes = [count for _, count in top_protocols]
        
        # Create colors
        colors = plt.cm.Set3(np.linspace(0, 1, len(labels)))
        
        # Create pie chart
        fig, ax = plt.subplots(figsize=(10, 8))
        
        wedges, texts, autotexts = ax.pie(
            sizes, 
            labels=labels, 
            colors=colors,
            autopct='%1.1f%%' if show_percentages else None,
            startangle=90,
            explode=[0.05] * len(labels)  # Slightly separate slices
        )
        
        # Enhance appearance
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontweight('bold')
        
        ax.set_title(f'Protocol Distribution ({len(packets)} packets)', 
                    fontsize=14, fontweight='bold', pad=20)
        
        # Add legend with packet counts
        legend_labels = [f'{label}: {count}' for label, count in top_protocols]
        ax.legend(wedges, legend_labels, title="Protocols", loc="center left", 
                 bbox_to_anchor=(1, 0, 0.5, 1))
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            self.logger.info(f"Protocol distribution saved to {save_path}")
        
        plt.show()
    
    def plot_traffic_over_time(self, packets: List[Any], 
                             interval: int = 1,
                             save_path: Optional[str] = None,
                             protocol_filter: Optional[str] = None) -> None:
        """
        Create a line chart of traffic over time.
        
        Args:
            packets (List): Packets to analyze
            interval (int): Time interval in seconds for grouping
            save_path (str, optional): Path to save the plot
            protocol_filter (str, optional): Filter by specific protocol
        
        Examples:
            >>> plot_traffic_over_time(packets, interval=5, protocol_filter="TCP")
        """
        if not packets:
            self.logger.warning("No packets to visualize")
            return
        
        # Filter packets if protocol specified
        if protocol_filter:
            packets = [p for p in packets if get_protocol_name(p).upper() == protocol_filter.upper()]
        
        # Extract timestamps
        timestamps = []
        for packet in packets:
            if hasattr(packet, 'time'):
                timestamps.append(packet.time)
        
        if not timestamps:
            self.logger.warning("No packets with timestamps found")
            return
        
        # Convert to datetime objects
        datetimes = [datetime.fromtimestamp(ts) for ts in timestamps]
        
        # Group by time intervals
        time_counts = Counter()
        base_time = min(datetimes)
        
        for dt in datetimes:
            # Calculate interval bucket
            seconds_diff = (dt - base_time).total_seconds()
            bucket = int(seconds_diff // interval) * interval
            bucket_time = base_time.timestamp() + bucket
            time_counts[bucket_time] += 1
        
        # Prepare data for plotting
        times = sorted(time_counts.keys())
        counts = [time_counts[t] for t in times]
        datetime_times = [datetime.fromtimestamp(t) for t in times]
        
        # Create line chart
        fig, ax = plt.subplots(figsize=(12, 6))
        
        ax.plot(datetime_times, counts, marker='o', linewidth=2, markersize=4)
        ax.fill_between(datetime_times, counts, alpha=0.3)
        
        # Format x-axis
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
        ax.xaxis.set_major_locator(mdates.SecondLocator(interval=max(1, len(times)//10)))
        plt.xticks(rotation=45)
        
        # Labels and title
        protocol_str = f" ({protocol_filter})" if protocol_filter else ""
        ax.set_title(f'Traffic Over Time{protocol_str} (interval: {interval}s)', 
                    fontsize=14, fontweight='bold')
        ax.set_xlabel('Time')
        ax.set_ylabel('Packets per Interval')
        
        # Add statistics
        avg_rate = np.mean(counts)
        max_rate = max(counts)
        ax.axhline(y=avg_rate, color='red', linestyle='--', alpha=0.7, 
                  label=f'Average: {avg_rate:.1f} pkt/interval')
        ax.legend()
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            self.logger.info(f"Traffic over time saved to {save_path}")
        
        plt.show()
    
    def plot_packet_sizes(self, packets: List[Any],
                         save_path: Optional[str] = None,
                         bins: int = 30) -> None:
        """
        Create a histogram of packet sizes.
        
        Args:
            packets (List): Packets to analyze
            save_path (str, optional): Path to save the plot
            bins (int): Number of histogram bins
        """
        if not packets:
            self.logger.warning("No packets to visualize")
            return
        
        # Extract packet sizes
        sizes = [len(packet) for packet in packets if hasattr(packet, '__len__')]
        
        if not sizes:
            self.logger.warning("No packets with size information found")
            return
        
        # Create histogram
        fig, ax = plt.subplots(figsize=(10, 6))
        
        n, bins_edges, patches = ax.hist(sizes, bins=bins, alpha=0.7, edgecolor='black')
        
        # Color bars based on size ranges
        for i, patch in enumerate(patches):
            bin_center = (bins_edges[i] + bins_edges[i+1]) / 2
            if bin_center <= 64:
                patch.set_facecolor('lightblue')
            elif bin_center <= 512:
                patch.set_facecolor('lightgreen')
            elif bin_center <= 1500:
                patch.set_facecolor('orange')
            else:
                patch.set_facecolor('red')
        
        # Statistics
        mean_size = np.mean(sizes)
        median_size = np.median(sizes)
        
        ax.axvline(mean_size, color='red', linestyle='--', linewidth=2, 
                  label=f'Mean: {mean_size:.0f} bytes')
        ax.axvline(median_size, color='green', linestyle='--', linewidth=2,
                  label=f'Median: {median_size:.0f} bytes')
        
        ax.set_title(f'Packet Size Distribution ({len(packets)} packets)', 
                    fontsize=14, fontweight='bold')
        ax.set_xlabel('Packet Size (bytes)')
        ax.set_ylabel('Frequency')
        ax.legend()
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            self.logger.info(f"Packet sizes histogram saved to {save_path}")
        
        plt.show()
    
    def plot_top_talkers(self, packets: List[Any], 
                        save_path: Optional[str] = None,
                        top_n: int = 10) -> None:
        """
        Create a bar chart of top talking IP addresses.
        
        Args:
            packets (List): Packets to analyze
            save_path (str, optional): Path to save the plot
            top_n (int): Number of top talkers to show
        """
        if not packets:
            self.logger.warning("No packets to visualize")
            return
        
        # Count traffic per IP
        ip_traffic = Counter()
        
        for packet in packets:
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                size = len(packet) if hasattr(packet, '__len__') else 0
                ip_traffic[ip_layer.src] += size
        
        if not ip_traffic:
            self.logger.warning("No IP packets found")
            return
        
        # Get top talkers
        top_talkers = ip_traffic.most_common(top_n)
        
        # Prepare data
        ips = [ip for ip, _ in top_talkers]
        sizes = [size for _, size in top_talkers]
        
        # Create bar chart
        fig, ax = plt.subplots(figsize=(12, 6))
        
        bars = ax.bar(range(len(ips)), sizes, color='skyblue', edgecolor='navy')
        
        # Customize appearance
        ax.set_title(f'Top {top_n} Talking IP Addresses', fontsize=14, fontweight='bold')
        ax.set_xlabel('IP Addresses')
        ax.set_ylabel('Bytes Sent')
        ax.set_xticks(range(len(ips)))
        ax.set_xticklabels(ips, rotation=45, ha='right')
        
        # Add value labels on bars
        for i, (bar, size) in enumerate(zip(bars, sizes)):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + max(sizes)*0.01,
                   format_bytes(size), ha='center', va='bottom', fontsize=9)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            self.logger.info(f"Top talkers chart saved to {save_path}")
        
        plt.show()
    
    def plot_port_usage(self, packets: List[Any],
                       save_path: Optional[str] = None,
                       top_n: int = 15,
                       protocol: Optional[str] = None) -> None:
        """
        Create a bar chart of port usage.
        
        Args:
            packets (List): Packets to analyze
            save_path (str, optional): Path to save the plot
            top_n (int): Number of top ports to show
            protocol (str, optional): Filter by protocol (TCP/UDP)
        """
        if not packets:
            self.logger.warning("No packets to visualize")
            return
        
        # Count port usage
        port_counts = Counter()
        
        for packet in packets:
            if protocol and get_protocol_name(packet).upper() != protocol.upper():
                continue
                
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                port_counts[tcp_layer.dport] += 1
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                port_counts[udp_layer.dport] += 1
        
        if not port_counts:
            self.logger.warning("No TCP/UDP packets found")
            return
        
        # Get top ports
        top_ports = port_counts.most_common(top_n)
        
        # Prepare data
        ports = [str(port) for port, _ in top_ports]
        counts = [count for _, count in top_ports]
        
        # Create bar chart
        fig, ax = plt.subplots(figsize=(12, 6))
        
        bars = ax.bar(range(len(ports)), counts, color='lightcoral', edgecolor='darkred')
        
        # Customize appearance
        protocol_str = f" ({protocol})" if protocol else ""
        ax.set_title(f'Top {top_n} Destination Ports{protocol_str}', 
                    fontsize=14, fontweight='bold')
        ax.set_xlabel('Port Numbers')
        ax.set_ylabel('Packet Count')
        ax.set_xticks(range(len(ports)))
        ax.set_xticklabels(ports, rotation=45)
        
        # Add value labels on bars
        for bar, count in zip(bars, counts):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + max(counts)*0.01,
                   str(count), ha='center', va='bottom', fontsize=9)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            self.logger.info(f"Port usage chart saved to {save_path}")
        
        plt.show()
    
    def create_dashboard(self, packets: List[Any], 
                        save_path: Optional[str] = None) -> None:
        """
        Create a comprehensive dashboard with multiple visualizations.
        
        Args:
            packets (List): Packets to analyze
            save_path (str, optional): Path to save the dashboard
        """
        if not packets:
            self.logger.warning("No packets to visualize")
            return
        
        # Create figure with subplots
        fig = plt.figure(figsize=(16, 12))
        
        # Protocol distribution (top-left)
        ax1 = plt.subplot(2, 3, 1)
        protocol_counts = Counter(get_protocol_name(p) for p in packets)
        top_protocols = protocol_counts.most_common(6)
        
        if len(protocol_counts) > 6:
            others = sum(count for _, count in protocol_counts.most_common()[6:])
            top_protocols.append(("Others", others))
        
        labels = [proto for proto, _ in top_protocols]
        sizes = [count for _, count in top_protocols]
        colors = plt.cm.Set3(np.linspace(0, 1, len(labels)))
        
        ax1.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
        ax1.set_title('Protocol Distribution', fontweight='bold')
        
        # Packet sizes (top-middle)
        ax2 = plt.subplot(2, 3, 2)
        sizes = [len(p) for p in packets if hasattr(p, '__len__')]
        if sizes:
            ax2.hist(sizes, bins=20, alpha=0.7, color='skyblue', edgecolor='black')
            ax2.axvline(np.mean(sizes), color='red', linestyle='--', label=f'Mean: {np.mean(sizes):.0f}')
            ax2.set_title('Packet Size Distribution', fontweight='bold')
            ax2.set_xlabel('Size (bytes)')
            ax2.set_ylabel('Frequency')
            ax2.legend()
        
        # Top talkers (top-right)
        ax3 = plt.subplot(2, 3, 3)
        ip_traffic = Counter()
        for packet in packets:
            if packet.haslayer(IP):
                size = len(packet) if hasattr(packet, '__len__') else 0
                ip_traffic[packet[IP].src] += size
        
        if ip_traffic:
            top_ips = ip_traffic.most_common(5)
            ips = [ip[-8:] + '...' if len(ip) > 11 else ip for ip, _ in top_ips]  # Truncate IPs
            traffic = [size for _, size in top_ips]
            
            ax3.barh(range(len(ips)), traffic, color='lightgreen')
            ax3.set_yticks(range(len(ips)))
            ax3.set_yticklabels(ips)
            ax3.set_title('Top Talkers (bytes sent)', fontweight='bold')
            ax3.set_xlabel('Bytes')
        
        # Traffic over time (bottom-left, spanning 2 columns)
        ax4 = plt.subplot(2, 3, (4, 5))
        timestamps = [p.time for p in packets if hasattr(p, 'time')]
        if timestamps:
            timestamps.sort()
            # Group by 5-second intervals
            time_counts = Counter()
            base_time = min(timestamps)
            
            for ts in timestamps:
                bucket = int((ts - base_time) // 5) * 5
                time_counts[base_time + bucket] += 1
            
            times = sorted(time_counts.keys())
            counts = [time_counts[t] for t in times]
            datetime_times = [datetime.fromtimestamp(t) for t in times]
            
            ax4.plot(datetime_times, counts, marker='o', linewidth=2)
            ax4.fill_between(datetime_times, counts, alpha=0.3)
            ax4.set_title('Traffic Over Time (5s intervals)', fontweight='bold')
            ax4.set_xlabel('Time')
            ax4.set_ylabel('Packets')
            plt.setp(ax4.xaxis.get_majorticklabels(), rotation=45)
        
        # Port usage (bottom-right)
        ax5 = plt.subplot(2, 3, 6)
        port_counts = Counter()
        for packet in packets:
            if packet.haslayer(TCP):
                port_counts[packet[TCP].dport] += 1
            elif packet.haslayer(UDP):
                port_counts[packet[UDP].dport] += 1
        
        if port_counts:
            top_ports = port_counts.most_common(8)
            ports = [str(port) for port, _ in top_ports]
            counts = [count for _, count in top_ports]
            
            ax5.bar(range(len(ports)), counts, color='orange')
            ax5.set_xticks(range(len(ports)))
            ax5.set_xticklabels(ports, rotation=45)
            ax5.set_title('Top Destination Ports', fontweight='bold')
            ax5.set_xlabel('Port')
            ax5.set_ylabel('Packets')
        
        # Add main title
        fig.suptitle(f'Network Traffic Analysis Dashboard - {len(packets)} packets', 
                    fontsize=16, fontweight='bold', y=0.95)
        
        plt.tight_layout()
        plt.subplots_adjust(top=0.92)
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            self.logger.info(f"Dashboard saved to {save_path}")
        
        plt.show()


# Convenience functions
def plot_protocol_distribution(packets: List[Any], save_path: Optional[str] = None) -> None:
    """
    Create protocol distribution pie chart (convenience function).
    
    Args:
        packets (List): Packets to analyze
        save_path (str, optional): Path to save the plot
    
    Examples:
        >>> plot_protocol_distribution(packets, "protocols.png")
    """
    visualizer = PacketVisualizer()
    visualizer.plot_protocol_distribution(packets, save_path)


def plot_traffic_over_time(packets: List[Any], interval: int = 1, 
                          save_path: Optional[str] = None) -> None:
    """
    Create traffic over time line chart (convenience function).
    
    Args:
        packets (List): Packets to analyze
        interval (int): Time interval in seconds
        save_path (str, optional): Path to save the plot
    
    Examples:
        >>> plot_traffic_over_time(packets, interval=5, save_path="traffic.png")
    """
    visualizer = PacketVisualizer()
    visualizer.plot_traffic_over_time(packets, interval, save_path)


def create_analysis_dashboard(packets: List[Any], save_path: Optional[str] = None) -> None:
    """
    Create comprehensive analysis dashboard (convenience function).
    
    Args:
        packets (List): Packets to analyze
        save_path (str, optional): Path to save the dashboard
    
    Examples:
        >>> create_analysis_dashboard(packets, "dashboard.png")
    """
    visualizer = PacketVisualizer()
    visualizer.create_dashboard(packets, save_path)


def save_all_plots(packets: List[Any], output_dir: str = "plots") -> None:
    """
    Generate and save all available plots.
    
    Args:
        packets (List): Packets to analyze
        output_dir (str): Directory to save plots
    
    Examples:
        >>> save_all_plots(packets, "analysis_plots")
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    visualizer = PacketVisualizer()
    
    # Generate all plots
    visualizer.plot_protocol_distribution(packets, f"{output_dir}/protocol_distribution.png")
    visualizer.plot_traffic_over_time(packets, save_path=f"{output_dir}/traffic_over_time.png")
    visualizer.plot_packet_sizes(packets, save_path=f"{output_dir}/packet_sizes.png")
    visualizer.plot_top_talkers(packets, save_path=f"{output_dir}/top_talkers.png")
    visualizer.plot_port_usage(packets, save_path=f"{output_dir}/port_usage.png")
    visualizer.create_dashboard(packets, save_path=f"{output_dir}/dashboard.png")
    
    print(f"All plots saved to {output_dir}/")


# Visualization presets
VISUALIZATION_PRESETS = {
    'basic': ['protocol_distribution', 'traffic_over_time'],
    'security': ['protocol_distribution', 'top_talkers', 'port_usage'],
    'performance': ['packet_sizes', 'traffic_over_time', 'top_talkers'],
    'comprehensive': ['dashboard']
}


def quick_visualize(packets: List[Any], preset: str = 'basic', 
                   output_dir: str = "plots") -> None:
    """
    Quick visualization using presets.
    
    Args:
        packets (List): Packets to analyze
        preset (str): Visualization preset name
        output_dir (str): Output directory
    
    Examples:
        >>> quick_visualize(packets, 'security', 'security_analysis')
    """
    if preset not in VISUALIZATION_PRESETS:
        raise ValueError(f"Unknown preset: {preset}. Available: {list(VISUALIZATION_PRESETS.keys())}")
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    visualizer = PacketVisualizer()
    plot_types = VISUALIZATION_PRESETS[preset]
    
    for plot_type in plot_types:
        save_path = f"{output_dir}/{plot_type}.png"
        
        if plot_type == 'protocol_distribution':
            visualizer.plot_protocol_distribution(packets, save_path)
        elif plot_type == 'traffic_over_time':
            visualizer.plot_traffic_over_time(packets, save_path=save_path)
        elif plot_type == 'packet_sizes':
            visualizer.plot_packet_sizes(packets, save_path)
        elif plot_type == 'top_talkers':
            visualizer.plot_top_talkers(packets, save_path)
        elif plot_type == 'port_usage':
            visualizer.plot_port_usage(packets, save_path)
        elif plot_type == 'dashboard':
            visualizer.create_dashboard(packets, save_path)
    
    print(f"Preset '{preset}' visualizations saved to {output_dir}/")