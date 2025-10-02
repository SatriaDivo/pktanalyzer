"""
PktAnalyzer Analysis Module

This module provides packet analysis and statistics functionality.
"""

from typing import List, Dict, Any, Union, Optional
from collections import Counter, defaultdict
import statistics
from datetime import datetime

try:
    from scapy.all import Packet
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import ARP, Ether
except ImportError:
    raise ImportError("Scapy is required. Install with: pip install scapy")

from .utils import setup_logging, format_bytes, get_protocol_name


class PacketAnalyzer:
    """
    Main packet analysis class providing comprehensive packet statistics.
    """
    
    def __init__(self, verbose: bool = False):
        """
        Initialize packet analyzer.
        
        Args:
            verbose (bool): Enable verbose logging
        """
        self.verbose = verbose
        self.logger = setup_logging(verbose)
        
    def analyze_packets(self, packets: List[Any]) -> Dict[str, Any]:
        """
        Perform comprehensive analysis of packet list.
        
        Args:
            packets (List): List of packets to analyze
        
        Returns:
            Dict: Comprehensive analysis results
        
        Raises:
            ValueError: If no packets provided
        """
        if not packets:
            raise ValueError("No packets to analyze")
        
        self.logger.info(f"Analyzing {len(packets)} packets")
        
        analysis = {
            'summary': self._get_basic_stats(packets),
            'protocols': self._analyze_protocols(packets),
            'ip_stats': self._analyze_ip_traffic(packets),
            'size_stats': self._analyze_packet_sizes(packets),
            'time_stats': self._analyze_timing(packets),
            'top_talkers': self._get_top_talkers(packets),
            'port_stats': self._analyze_ports(packets)
        }
        
        self.logger.info("Analysis completed")
        return analysis
    
    def _get_basic_stats(self, packets: List[Any]) -> Dict[str, Any]:
        """Get basic packet statistics."""
        total_packets = len(packets)
        total_size = sum(len(pkt) for pkt in packets if hasattr(pkt, '__len__'))
        
        return {
            'total_packets': total_packets,
            'total_size_bytes': total_size,
            'total_size_human': format_bytes(total_size),
            'average_packet_size': total_size / total_packets if total_packets > 0 else 0
        }
    
    def _analyze_protocols(self, packets: List[Any]) -> Dict[str, Any]:
        """Analyze protocol distribution."""
        protocol_counts = Counter()
        protocol_sizes = defaultdict(int)
        
        for packet in packets:
            proto = get_protocol_name(packet)
            protocol_counts[proto] += 1
            protocol_sizes[proto] += len(packet) if hasattr(packet, '__len__') else 0
        
        total_packets = len(packets)
        
        protocols = {}
        for proto, count in protocol_counts.items():
            protocols[proto] = {
                'count': count,
                'percentage': (count / total_packets) * 100,
                'total_size': protocol_sizes[proto],
                'avg_size': protocol_sizes[proto] / count if count > 0 else 0
            }
        
        return {
            'distribution': protocols,
            'most_common': protocol_counts.most_common(5)
        }
    
    def _analyze_ip_traffic(self, packets: List[Any]) -> Dict[str, Any]:
        """Analyze IP traffic patterns."""
        src_ips = Counter()
        dst_ips = Counter()
        ip_pairs = Counter()
        
        for packet in packets:
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                src = ip_layer.src
                dst = ip_layer.dst
                
                src_ips[src] += 1
                dst_ips[dst] += 1
                ip_pairs[(src, dst)] += 1
        
        return {
            'unique_source_ips': len(src_ips),
            'unique_destination_ips': len(dst_ips),
            'top_source_ips': src_ips.most_common(10),
            'top_destination_ips': dst_ips.most_common(10),
            'top_conversations': ip_pairs.most_common(10)
        }
    
    def _analyze_packet_sizes(self, packets: List[Any]) -> Dict[str, Any]:
        """Analyze packet size statistics."""
        sizes = [len(pkt) for pkt in packets if hasattr(pkt, '__len__')]
        
        if not sizes:
            return {}
        
        return {
            'min_size': min(sizes),
            'max_size': max(sizes),
            'average_size': statistics.mean(sizes),
            'median_size': statistics.median(sizes),
            'std_deviation': statistics.stdev(sizes) if len(sizes) > 1 else 0,
            'size_distribution': self._get_size_distribution(sizes)
        }
    
    def _get_size_distribution(self, sizes: List[int]) -> Dict[str, int]:
        """Get packet size distribution in bins."""
        bins = {
            'tiny (0-64)': 0,
            'small (65-128)': 0,
            'medium (129-512)': 0,
            'large (513-1024)': 0,
            'jumbo (1025+)': 0
        }
        
        for size in sizes:
            if size <= 64:
                bins['tiny (0-64)'] += 1
            elif size <= 128:
                bins['small (65-128)'] += 1
            elif size <= 512:
                bins['medium (129-512)'] += 1
            elif size <= 1024:
                bins['large (513-1024)'] += 1
            else:
                bins['jumbo (1025+)'] += 1
        
        return bins
    
    def _analyze_timing(self, packets: List[Any]) -> Dict[str, Any]:
        """Analyze packet timing."""
        timestamps = []
        
        for packet in packets:
            if hasattr(packet, 'time'):
                timestamps.append(packet.time)
        
        if len(timestamps) < 2:
            return {'capture_duration': 0, 'packets_per_second': 0}
        
        timestamps.sort()
        duration = timestamps[-1] - timestamps[0]
        
        # Calculate inter-arrival times
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        
        return {
            'capture_duration': duration,
            'packets_per_second': len(packets) / duration if duration > 0 else 0,
            'average_interval': statistics.mean(intervals) if intervals else 0,
            'min_interval': min(intervals) if intervals else 0,
            'max_interval': max(intervals) if intervals else 0,
            'first_packet_time': datetime.fromtimestamp(timestamps[0]).isoformat(),
            'last_packet_time': datetime.fromtimestamp(timestamps[-1]).isoformat()
        }
    
    def _get_top_talkers(self, packets: List[Any], top_n: int = 10) -> Dict[str, Any]:
        """Identify top talking IP addresses."""
        ip_traffic = defaultdict(lambda: {'sent': 0, 'received': 0, 'total': 0})
        
        for packet in packets:
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                src = ip_layer.src
                dst = ip_layer.dst
                size = len(packet) if hasattr(packet, '__len__') else 0
                
                ip_traffic[src]['sent'] += size
                ip_traffic[src]['total'] += size
                ip_traffic[dst]['received'] += size
                ip_traffic[dst]['total'] += size
        
        # Sort by total traffic
        sorted_ips = sorted(ip_traffic.items(), key=lambda x: x[1]['total'], reverse=True)
        
        return {
            'top_by_total': sorted_ips[:top_n],
            'top_senders': sorted(ip_traffic.items(), key=lambda x: x[1]['sent'], reverse=True)[:top_n],
            'top_receivers': sorted(ip_traffic.items(), key=lambda x: x[1]['received'], reverse=True)[:top_n]
        }
    
    def _analyze_ports(self, packets: List[Any]) -> Dict[str, Any]:
        """Analyze port usage."""
        src_ports = Counter()
        dst_ports = Counter()
        port_pairs = Counter()
        
        for packet in packets:
            src_port = None
            dst_port = None
            
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
            
            if src_port and dst_port:
                src_ports[src_port] += 1
                dst_ports[dst_port] += 1
                port_pairs[(src_port, dst_port)] += 1
        
        return {
            'top_source_ports': src_ports.most_common(10),
            'top_destination_ports': dst_ports.most_common(10),
            'top_port_pairs': port_pairs.most_common(10),
            'well_known_services': self._identify_services(dst_ports)
        }
    
    def _identify_services(self, port_counts: Counter) -> Dict[str, int]:
        """Identify well-known services from port usage."""
        well_known_ports = {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
            25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            993: 'IMAPS', 995: 'POP3S', 587: 'SMTP', 465: 'SMTPS'
        }
        
        services = {}
        for port, count in port_counts.items():
            if port in well_known_ports:
                services[well_known_ports[port]] = count
        
        return services


def analyze_packets(packets: List[Any], verbose: bool = False) -> Dict[str, Any]:
    """
    Analyze packets and return comprehensive statistics.
    
    Args:
        packets (List): List of packets to analyze
        verbose (bool): Enable verbose logging
    
    Returns:
        Dict: Analysis results
    
    Examples:
        >>> packets = capture_packets(count=100)
        >>> stats = analyze_packets(packets)
        >>> print(f"Total packets: {stats['summary']['total_packets']}")
    """
    analyzer = PacketAnalyzer(verbose=verbose)
    return analyzer.analyze_packets(packets)


def summarize_packet(packet: Any) -> Dict[str, Any]:
    """
    Create a summary of a single packet.
    
    Args:
        packet: Packet to summarize
    
    Returns:
        Dict: Packet summary
    
    Examples:
        >>> packet = packets[0]
        >>> summary = summarize_packet(packet)
        >>> print(f"Protocol: {summary['protocol']}")
    """
    summary = {
        'timestamp': None,
        'src_ip': None,
        'dst_ip': None,
        'src_port': None,
        'dst_port': None,
        'protocol': get_protocol_name(packet),
        'length': len(packet) if hasattr(packet, '__len__') else 0,
        'summary': packet.summary() if hasattr(packet, 'summary') else str(packet)
    }
    
    # Extract timestamp
    if hasattr(packet, 'time'):
        summary['timestamp'] = datetime.fromtimestamp(packet.time).isoformat()
    
    # Extract IP information
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        summary['src_ip'] = ip_layer.src
        summary['dst_ip'] = ip_layer.dst
    
    # Extract port information
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        summary['src_port'] = tcp_layer.sport
        summary['dst_port'] = tcp_layer.dport
        summary['tcp_flags'] = tcp_layer.flags
    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        summary['src_port'] = udp_layer.sport
        summary['dst_port'] = udp_layer.dport
    
    # Extract additional protocol-specific info
    if packet.haslayer(ICMP):
        icmp_layer = packet[ICMP]
        summary['icmp_type'] = icmp_layer.type
        summary['icmp_code'] = icmp_layer.code
    elif packet.haslayer(ARP):
        arp_layer = packet[ARP]
        summary['arp_op'] = arp_layer.op
        summary['arp_psrc'] = arp_layer.psrc
        summary['arp_pdst'] = arp_layer.pdst
    
    return summary


def get_protocol_stats(packets: List[Any]) -> Dict[str, int]:
    """
    Get protocol distribution statistics.
    
    Args:
        packets (List): List of packets
    
    Returns:
        Dict: Protocol counts
    
    Examples:
        >>> packets = capture_packets(count=100)
        >>> proto_stats = get_protocol_stats(packets)
        >>> print(f"TCP packets: {proto_stats.get('TCP', 0)}")
    """
    protocol_counts = Counter()
    
    for packet in packets:
        proto = get_protocol_name(packet)
        protocol_counts[proto] += 1
    
    return dict(protocol_counts)


def get_top_talkers(packets: List[Any], top_n: int = 10) -> List[tuple]:
    """
    Get top talking IP addresses by traffic volume.
    
    Args:
        packets (List): List of packets
        top_n (int): Number of top talkers to return
    
    Returns:
        List[tuple]: List of (IP, bytes_transferred) tuples
    
    Examples:
        >>> packets = capture_packets(count=100)
        >>> talkers = get_top_talkers(packets, 5)
        >>> for ip, bytes_sent in talkers:
        ...     print(f"{ip}: {bytes_sent} bytes")
    """
    ip_traffic = defaultdict(int)
    
    for packet in packets:
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            size = len(packet) if hasattr(packet, '__len__') else 0
            ip_traffic[ip_layer.src] += size
    
    return sorted(ip_traffic.items(), key=lambda x: x[1], reverse=True)[:top_n]


class SecurityAnalyzer:
    """
    Security-focused packet analysis for educational purposes.
    """
    
    def __init__(self, verbose: bool = False):
        """Initialize security analyzer."""
        self.verbose = verbose
        self.logger = setup_logging(verbose)
    
    def detect_syn_flood(self, packets: List[Any], threshold: int = 100) -> Dict[str, Any]:
        """
        Detect potential SYN flood attacks.
        
        Args:
            packets (List): Packets to analyze
            threshold (int): SYN packets threshold per source IP
        
        Returns:
            Dict: SYN flood analysis results
        """
        syn_counts = Counter()
        
        for packet in packets:
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                # Check for SYN flag (bit 1)
                if tcp_layer.flags & 0x02:  # SYN flag
                    if packet.haslayer(IP):
                        src_ip = packet[IP].src
                        syn_counts[src_ip] += 1
        
        potential_attackers = {ip: count for ip, count in syn_counts.items() if count > threshold}
        
        return {
            'total_syn_packets': sum(syn_counts.values()),
            'unique_sources': len(syn_counts),
            'potential_syn_flood_sources': potential_attackers,
            'top_syn_sources': syn_counts.most_common(10)
        }
    
    def detect_icmp_flood(self, packets: List[Any], threshold: int = 50) -> Dict[str, Any]:
        """
        Detect potential ICMP flood attacks.
        
        Args:
            packets (List): Packets to analyze
            threshold (int): ICMP packets threshold per source IP
        
        Returns:
            Dict: ICMP flood analysis results
        """
        icmp_counts = Counter()
        icmp_types = Counter()
        
        for packet in packets:
            if packet.haslayer(ICMP):
                if packet.haslayer(IP):
                    src_ip = packet[IP].src
                    icmp_counts[src_ip] += 1
                
                icmp_layer = packet[ICMP]
                icmp_types[icmp_layer.type] += 1
        
        potential_attackers = {ip: count for ip, count in icmp_counts.items() if count > threshold}
        
        return {
            'total_icmp_packets': sum(icmp_counts.values()),
            'icmp_types': dict(icmp_types),
            'potential_icmp_flood_sources': potential_attackers,
            'top_icmp_sources': icmp_counts.most_common(10)
        }
    
    def analyze_port_scans(self, packets: List[Any]) -> Dict[str, Any]:
        """
        Analyze potential port scanning activity.
        
        Args:
            packets (List): Packets to analyze
        
        Returns:
            Dict: Port scan analysis results
        """
        # Track unique ports accessed per source IP
        ip_ports = defaultdict(set)
        
        for packet in packets:
            if packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP)):
                src_ip = packet[IP].src
                
                if packet.haslayer(TCP):
                    dst_port = packet[TCP].dport
                elif packet.haslayer(UDP):
                    dst_port = packet[UDP].dport
                
                ip_ports[src_ip].add(dst_port)
        
        # Identify potential scanners (accessing many different ports)
        potential_scanners = {}
        for ip, ports in ip_ports.items():
            if len(ports) > 20:  # Threshold for port scanning
                potential_scanners[ip] = len(ports)
        
        return {
            'potential_port_scanners': potential_scanners,
            'top_port_accessors': sorted(
                [(ip, len(ports)) for ip, ports in ip_ports.items()],
                key=lambda x: x[1], reverse=True
            )[:10]
        }


def detect_anomalies(packets: List[Any], verbose: bool = False) -> Dict[str, Any]:
    """
    Detect various network anomalies for educational purposes.
    
    Args:
        packets (List): Packets to analyze
        verbose (bool): Enable verbose logging
    
    Returns:
        Dict: Anomaly detection results
    
    Examples:
        >>> packets = capture_packets(count=1000)
        >>> anomalies = detect_anomalies(packets)
        >>> if anomalies['syn_flood']['potential_syn_flood_sources']:
        ...     print("Potential SYN flood detected!")
    """
    analyzer = SecurityAnalyzer(verbose=verbose)
    
    return {
        'syn_flood': analyzer.detect_syn_flood(packets),
        'icmp_flood': analyzer.detect_icmp_flood(packets),
        'port_scans': analyzer.analyze_port_scans(packets)
    }