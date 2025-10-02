"""
PktAnalyzer Filters Module

This module provides packet filtering functionality.
"""

from typing import List, Any, Optional, Union
import ipaddress

try:
    from scapy.all import Packet
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import ARP, Ether
except ImportError:
    raise ImportError("Scapy is required. Install with: pip install scapy")

from .utils import setup_logging, get_protocol_name


class PacketFilter:
    """
    Advanced packet filtering class with multiple filter criteria.
    """
    
    def __init__(self, verbose: bool = False):
        """
        Initialize packet filter.
        
        Args:
            verbose (bool): Enable verbose logging
        """
        self.verbose = verbose
        self.logger = setup_logging(verbose)
    
    def filter_by_ip(self, packets: List[Any], ip: str, 
                     direction: str = "both") -> List[Any]:
        """
        Filter packets by IP address.
        
        Args:
            packets (List): Packets to filter
            ip (str): IP address to filter by
            direction (str): "src", "dst", or "both"
        
        Returns:
            List: Filtered packets
        
        Raises:
            ValueError: If invalid IP or direction
        """
        try:
            # Validate IP address
            ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError(f"Invalid IP address: {ip}")
        
        if direction not in ["src", "dst", "both"]:
            raise ValueError("Direction must be 'src', 'dst', or 'both'")
        
        filtered_packets = []
        
        for packet in packets:
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                
                if direction == "src" and ip_layer.src == ip:
                    filtered_packets.append(packet)
                elif direction == "dst" and ip_layer.dst == ip:
                    filtered_packets.append(packet)
                elif direction == "both" and (ip_layer.src == ip or ip_layer.dst == ip):
                    filtered_packets.append(packet)
        
        self.logger.info(f"Filtered by IP {ip} ({direction}): {len(filtered_packets)} packets")
        return filtered_packets
    
    def filter_by_subnet(self, packets: List[Any], subnet: str,
                        direction: str = "both") -> List[Any]:
        """
        Filter packets by subnet.
        
        Args:
            packets (List): Packets to filter
            subnet (str): Subnet in CIDR notation (e.g., "192.168.1.0/24")
            direction (str): "src", "dst", or "both"
        
        Returns:
            List: Filtered packets
        
        Raises:
            ValueError: If invalid subnet or direction
        """
        try:
            network = ipaddress.ip_network(subnet, strict=False)
        except ValueError:
            raise ValueError(f"Invalid subnet: {subnet}")
        
        if direction not in ["src", "dst", "both"]:
            raise ValueError("Direction must be 'src', 'dst', or 'both'")
        
        filtered_packets = []
        
        for packet in packets:
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                
                try:
                    src_ip = ipaddress.ip_address(ip_layer.src)
                    dst_ip = ipaddress.ip_address(ip_layer.dst)
                    
                    if direction == "src" and src_ip in network:
                        filtered_packets.append(packet)
                    elif direction == "dst" and dst_ip in network:
                        filtered_packets.append(packet)
                    elif direction == "both" and (src_ip in network or dst_ip in network):
                        filtered_packets.append(packet)
                except ValueError:
                    continue  # Skip packets with invalid IPs
        
        self.logger.info(f"Filtered by subnet {subnet} ({direction}): {len(filtered_packets)} packets")
        return filtered_packets
    
    def filter_by_protocol(self, packets: List[Any], protocol: str) -> List[Any]:
        """
        Filter packets by protocol.
        
        Args:
            packets (List): Packets to filter
            protocol (str): Protocol name (tcp, udp, icmp, arp, etc.)
        
        Returns:
            List: Filtered packets
        
        Examples:
            >>> tcp_packets = filter_by_protocol(packets, "tcp")
            >>> udp_packets = filter_by_protocol(packets, "udp")
        """
        protocol = protocol.upper()
        filtered_packets = []
        
        for packet in packets:
            packet_protocol = get_protocol_name(packet).upper()
            if packet_protocol == protocol:
                filtered_packets.append(packet)
        
        self.logger.info(f"Filtered by protocol {protocol}: {len(filtered_packets)} packets")
        return filtered_packets
    
    def filter_by_port(self, packets: List[Any], port: int,
                      direction: str = "both", protocol: Optional[str] = None) -> List[Any]:
        """
        Filter packets by port number.
        
        Args:
            packets (List): Packets to filter
            port (int): Port number
            direction (str): "src", "dst", or "both"
            protocol (str, optional): Filter by protocol first ("tcp" or "udp")
        
        Returns:
            List: Filtered packets
        
        Examples:
            >>> http_packets = filter_by_port(packets, 80, "dst", "tcp")
            >>> dns_packets = filter_by_port(packets, 53, "both")
        """
        if not (1 <= port <= 65535):
            raise ValueError(f"Invalid port number: {port}")
        
        if direction not in ["src", "dst", "both"]:
            raise ValueError("Direction must be 'src', 'dst', or 'both'")
        
        filtered_packets = []
        
        for packet in packets:
            # Filter by protocol first if specified
            if protocol:
                packet_protocol = get_protocol_name(packet).upper()
                if packet_protocol != protocol.upper():
                    continue
            
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
            
            if src_port is not None and dst_port is not None:
                if direction == "src" and src_port == port:
                    filtered_packets.append(packet)
                elif direction == "dst" and dst_port == port:
                    filtered_packets.append(packet)
                elif direction == "both" and (src_port == port or dst_port == port):
                    filtered_packets.append(packet)
        
        proto_str = f" ({protocol})" if protocol else ""
        self.logger.info(f"Filtered by port {port}{proto_str} ({direction}): {len(filtered_packets)} packets")
        return filtered_packets
    
    def filter_by_size(self, packets: List[Any], min_size: int = 0,
                      max_size: int = 65535) -> List[Any]:
        """
        Filter packets by size range.
        
        Args:
            packets (List): Packets to filter
            min_size (int): Minimum packet size in bytes
            max_size (int): Maximum packet size in bytes
        
        Returns:
            List: Filtered packets
        """
        filtered_packets = []
        
        for packet in packets:
            size = len(packet) if hasattr(packet, '__len__') else 0
            if min_size <= size <= max_size:
                filtered_packets.append(packet)
        
        self.logger.info(f"Filtered by size {min_size}-{max_size}: {len(filtered_packets)} packets")
        return filtered_packets
    
    def filter_by_time_range(self, packets: List[Any], start_time: float,
                           end_time: float) -> List[Any]:
        """
        Filter packets by timestamp range.
        
        Args:
            packets (List): Packets to filter
            start_time (float): Start timestamp (Unix time)
            end_time (float): End timestamp (Unix time)
        
        Returns:
            List: Filtered packets
        """
        filtered_packets = []
        
        for packet in packets:
            if hasattr(packet, 'time'):
                if start_time <= packet.time <= end_time:
                    filtered_packets.append(packet)
        
        self.logger.info(f"Filtered by time range: {len(filtered_packets)} packets")
        return filtered_packets
    
    def filter_tcp_flags(self, packets: List[Any], flags: str) -> List[Any]:
        """
        Filter TCP packets by flags.
        
        Args:
            packets (List): Packets to filter
            flags (str): TCP flags to match ("SYN", "ACK", "FIN", etc.)
        
        Returns:
            List: Filtered packets
        
        Examples:
            >>> syn_packets = filter_tcp_flags(packets, "SYN")
            >>> syn_ack_packets = filter_tcp_flags(packets, "SYN+ACK")
        """
        filtered_packets = []
        
        # Parse flags
        flag_bits = {
            'FIN': 0x01, 'SYN': 0x02, 'RST': 0x04, 'PSH': 0x08,
            'ACK': 0x10, 'URG': 0x20, 'ECE': 0x40, 'CWR': 0x80
        }
        
        required_flags = 0
        for flag in flags.upper().split('+'):
            flag = flag.strip()
            if flag in flag_bits:
                required_flags |= flag_bits[flag]
        
        for packet in packets:
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                if (tcp_layer.flags & required_flags) == required_flags:
                    filtered_packets.append(packet)
        
        self.logger.info(f"Filtered by TCP flags {flags}: {len(filtered_packets)} packets")
        return filtered_packets
    
    def advanced_filter(self, packets: List[Any], **criteria) -> List[Any]:
        """
        Apply multiple filter criteria simultaneously.
        
        Args:
            packets (List): Packets to filter
            **criteria: Filter criteria (ip, protocol, port, size_min, size_max, etc.)
        
        Returns:
            List: Filtered packets
        
        Examples:
            >>> filtered = advanced_filter(packets, 
            ...                          protocol="tcp", 
            ...                          port=80, 
            ...                          ip="192.168.1.1")
        """
        result = packets.copy()
        
        # Apply IP filter
        if 'ip' in criteria:
            direction = criteria.get('ip_direction', 'both')
            result = self.filter_by_ip(result, criteria['ip'], direction)
        
        # Apply subnet filter
        if 'subnet' in criteria:
            direction = criteria.get('subnet_direction', 'both')
            result = self.filter_by_subnet(result, criteria['subnet'], direction)
        
        # Apply protocol filter
        if 'protocol' in criteria:
            result = self.filter_by_protocol(result, criteria['protocol'])
        
        # Apply port filter
        if 'port' in criteria:
            direction = criteria.get('port_direction', 'both')
            protocol = criteria.get('port_protocol', None)
            result = self.filter_by_port(result, criteria['port'], direction, protocol)
        
        # Apply size filter
        if 'size_min' in criteria or 'size_max' in criteria:
            min_size = criteria.get('size_min', 0)
            max_size = criteria.get('size_max', 65535)
            result = self.filter_by_size(result, min_size, max_size)
        
        # Apply TCP flags filter
        if 'tcp_flags' in criteria:
            result = self.filter_tcp_flags(result, criteria['tcp_flags'])
        
        self.logger.info(f"Advanced filter applied: {len(result)} packets remaining")
        return result


# Convenience functions
def filter_by_ip(packets: List[Any], ip: str, direction: str = "both") -> List[Any]:
    """
    Filter packets by IP address (convenience function).
    
    Args:
        packets (List): Packets to filter
        ip (str): IP address
        direction (str): "src", "dst", or "both"
    
    Returns:
        List: Filtered packets
    
    Examples:
        >>> local_packets = filter_by_ip(packets, "192.168.1.1")
        >>> outgoing = filter_by_ip(packets, "10.0.0.1", "src")
    """
    filter_obj = PacketFilter()
    return filter_obj.filter_by_ip(packets, ip, direction)


def filter_by_protocol(packets: List[Any], protocol: str) -> List[Any]:
    """
    Filter packets by protocol (convenience function).
    
    Args:
        packets (List): Packets to filter
        protocol (str): Protocol name
    
    Returns:
        List: Filtered packets
    
    Examples:
        >>> tcp_packets = filter_by_protocol(packets, "tcp")
        >>> udp_packets = filter_by_protocol(packets, "udp")
    """
    filter_obj = PacketFilter()
    return filter_obj.filter_by_protocol(packets, protocol)


def filter_by_port(packets: List[Any], port: int, direction: str = "both",
                  protocol: Optional[str] = None) -> List[Any]:
    """
    Filter packets by port (convenience function).
    
    Args:
        packets (List): Packets to filter
        port (int): Port number
        direction (str): "src", "dst", or "both"
        protocol (str, optional): Protocol filter
    
    Returns:
        List: Filtered packets
    
    Examples:
        >>> web_traffic = filter_by_port(packets, 80)
        >>> ssh_traffic = filter_by_port(packets, 22, "dst", "tcp")
    """
    filter_obj = PacketFilter()
    return filter_obj.filter_by_port(packets, port, direction, protocol)


def get_unique_ips(packets: List[Any], direction: str = "both") -> List[str]:
    """
    Get unique IP addresses from packets.
    
    Args:
        packets (List): Packets to analyze
        direction (str): "src", "dst", or "both"
    
    Returns:
        List[str]: Unique IP addresses
    
    Examples:
        >>> source_ips = get_unique_ips(packets, "src")
        >>> all_ips = get_unique_ips(packets, "both")
    """
    ips = set()
    
    for packet in packets:
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            
            if direction in ["src", "both"]:
                ips.add(ip_layer.src)
            if direction in ["dst", "both"]:
                ips.add(ip_layer.dst)
    
    return sorted(list(ips))


def get_unique_ports(packets: List[Any], direction: str = "both") -> List[int]:
    """
    Get unique port numbers from packets.
    
    Args:
        packets (List): Packets to analyze
        direction (str): "src", "dst", or "both"
    
    Returns:
        List[int]: Unique port numbers
    
    Examples:
        >>> ports = get_unique_ports(tcp_packets, "dst")
        >>> print(f"Destination ports seen: {ports}")
    """
    ports = set()
    
    for packet in packets:
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            if direction in ["src", "both"]:
                ports.add(tcp_layer.sport)
            if direction in ["dst", "both"]:
                ports.add(tcp_layer.dport)
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            if direction in ["src", "both"]:
                ports.add(udp_layer.sport)
            if direction in ["dst", "both"]:
                ports.add(udp_layer.dport)
    
    return sorted(list(ports))


def filter_conversations(packets: List[Any], ip1: str, ip2: str) -> List[Any]:
    """
    Filter packets for conversation between two IPs.
    
    Args:
        packets (List): Packets to filter
        ip1 (str): First IP address
        ip2 (str): Second IP address
    
    Returns:
        List: Packets in the conversation
    
    Examples:
        >>> conversation = filter_conversations(packets, "192.168.1.1", "10.0.0.1")
        >>> print(f"Conversation has {len(conversation)} packets")
    """
    filtered_packets = []
    
    for packet in packets:
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            src = ip_layer.src
            dst = ip_layer.dst
            
            if (src == ip1 and dst == ip2) or (src == ip2 and dst == ip1):
                filtered_packets.append(packet)
    
    return filtered_packets


# Predefined filter presets
FILTER_PRESETS = {
    'web_traffic': {'port': 80, 'protocol': 'tcp'},
    'secure_web': {'port': 443, 'protocol': 'tcp'},
    'dns_queries': {'port': 53},
    'ssh_traffic': {'port': 22, 'protocol': 'tcp'},
    'email_smtp': {'port': 25, 'protocol': 'tcp'},
    'email_pop3': {'port': 110, 'protocol': 'tcp'},
    'email_imap': {'port': 143, 'protocol': 'tcp'},
    'ftp_control': {'port': 21, 'protocol': 'tcp'},
    'telnet': {'port': 23, 'protocol': 'tcp'},
    'dhcp': {'port': 67},
    'broadcast': {'ip': '255.255.255.255', 'ip_direction': 'dst'},
    'syn_packets': {'tcp_flags': 'SYN', 'protocol': 'tcp'},
    'small_packets': {'size_max': 64},
    'large_packets': {'size_min': 1500}
}


def apply_preset_filter(packets: List[Any], preset_name: str) -> List[Any]:
    """
    Apply a predefined filter preset.
    
    Args:
        packets (List): Packets to filter
        preset_name (str): Name of the preset filter
    
    Returns:
        List: Filtered packets
    
    Examples:
        >>> web_packets = apply_preset_filter(packets, 'web_traffic')
        >>> dns_packets = apply_preset_filter(packets, 'dns_queries')
    """
    if preset_name not in FILTER_PRESETS:
        raise ValueError(f"Unknown preset: {preset_name}. Available: {list(FILTER_PRESETS.keys())}")
    
    filter_obj = PacketFilter()
    criteria = FILTER_PRESETS[preset_name]
    return filter_obj.advanced_filter(packets, **criteria)


def list_filter_presets() -> List[str]:
    """
    List available filter presets.
    
    Returns:
        List[str]: Available preset names
    """
    return list(FILTER_PRESETS.keys())