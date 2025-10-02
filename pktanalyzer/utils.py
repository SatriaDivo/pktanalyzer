"""
PktAnalyzer Utils Module

This module provides utility functions and helper classes.
"""

import json
import csv
import os
import logging
import time
from typing import Any, Dict, List, Optional, Union
from datetime import datetime

try:
    from scapy.all import rdpcap, Packet
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import ARP, Ether
except ImportError:
    raise ImportError("Scapy is required. Install with: pip install scapy")


def setup_logging(verbose: bool = False) -> logging.Logger:
    """
    Setup logging configuration for PktAnalyzer.
    
    Args:
        verbose (bool): Enable verbose logging
    
    Returns:
        logging.Logger: Configured logger
    """
    level = logging.DEBUG if verbose else logging.INFO
    
    # Configure logging format
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    logger = logging.getLogger('pktanalyzer')
    return logger


def get_protocol_name(packet: Any) -> str:
    """
    Get the protocol name from a packet.
    
    Args:
        packet: Scapy packet object
    
    Returns:
        str: Protocol name
    
    Examples:
        >>> protocol = get_protocol_name(packet)
        >>> print(f"Protocol: {protocol}")
    """
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    elif packet.haslayer(ARP):
        return "ARP"
    elif packet.haslayer(IP):
        return "IP"
    elif packet.haslayer(Ether):
        return "Ethernet"
    else:
        return "Unknown"


def format_bytes(bytes_count: int) -> str:
    """
    Format byte count into human-readable format.
    
    Args:
        bytes_count (int): Number of bytes
    
    Returns:
        str: Formatted byte string
    
    Examples:
        >>> print(format_bytes(1024))  # "1.0 KB"
        >>> print(format_bytes(1048576))  # "1.0 MB"
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.1f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.1f} PB"


def format_timestamp(timestamp: float, format_type: str = "iso") -> str:
    """
    Format timestamp into readable format.
    
    Args:
        timestamp (float): Unix timestamp
        format_type (str): Format type ("iso", "human", "short")
    
    Returns:
        str: Formatted timestamp
    
    Examples:
        >>> format_timestamp(time.time(), "human")
        >>> format_timestamp(time.time(), "iso")
    """
    dt = datetime.fromtimestamp(timestamp)
    
    if format_type == "iso":
        return dt.isoformat()
    elif format_type == "human":
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    elif format_type == "short":
        return dt.strftime("%H:%M:%S")
    else:
        return str(timestamp)


def validate_filter(filter_expr: str) -> bool:
    """
    Validate BPF filter expression (basic validation).
    
    Args:
        filter_expr (str): BPF filter expression
    
    Returns:
        bool: True if filter appears valid
    
    Examples:
        >>> validate_filter("tcp port 80")  # True
        >>> validate_filter("invalid syntax")  # False
    """
    if not filter_expr or not isinstance(filter_expr, str):
        return False
    
    # Basic validation - check for common BPF keywords
    valid_keywords = [
        'tcp', 'udp', 'icmp', 'arp', 'ip', 'port', 'host', 'net', 'src', 'dst',
        'and', 'or', 'not', 'broadcast', 'multicast', 'less', 'greater'
    ]
    
    # Split filter into tokens and check if they contain valid keywords
    tokens = filter_expr.lower().split()
    
    # Allow numeric values (ports, IPs)
    for token in tokens:
        if any(keyword in token for keyword in valid_keywords):
            continue
        if token.replace('.', '').replace(':', '').isdigit():
            continue
        if token in ['(', ')', '==', '!=', '<', '>', '<=', '>=']:
            continue
        # If we get here, token might be invalid, but let's be permissive
    
    return True


def load_pcap(filename: str) -> List[Any]:
    """
    Load packets from PCAP file.
    
    Args:
        filename (str): Path to PCAP file
    
    Returns:
        List: Loaded packets
    
    Raises:
        FileNotFoundError: If file doesn't exist
        IOError: If file can't be read
    
    Examples:
        >>> packets = load_pcap("capture.pcap")
        >>> print(f"Loaded {len(packets)} packets")
    """
    if not os.path.exists(filename):
        raise FileNotFoundError(f"PCAP file not found: {filename}")
    
    try:
        packets = rdpcap(filename)
        logger = setup_logging()
        logger.info(f"Loaded {len(packets)} packets from {filename}")
        return packets
    except Exception as e:
        raise IOError(f"Failed to load PCAP file: {str(e)}")


def export_stats(stats: Dict[str, Any], filename: str = "stats.json",
                format_type: str = "json") -> bool:
    """
    Export statistics to file.
    
    Args:
        stats (dict): Statistics data to export
        filename (str): Output filename
        format_type (str): Export format ("json" or "csv")
    
    Returns:
        bool: True if export successful
    
    Raises:
        ValueError: If format_type is invalid
        IOError: If file operations fail
    
    Examples:
        >>> stats = analyze_packets(packets)
        >>> export_stats(stats, "analysis.json")
        >>> export_stats(stats, "analysis.csv", "csv")
    """
    if format_type not in ["json", "csv"]:
        raise ValueError("format_type must be 'json' or 'csv'")
    
    try:
        if format_type == "json":
            return _export_json(stats, filename)
        else:
            return _export_csv(stats, filename)
    except Exception as e:
        raise IOError(f"Failed to export stats: {str(e)}")


def _export_json(stats: Dict[str, Any], filename: str) -> bool:
    """Export statistics to JSON file."""
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2, default=str, ensure_ascii=False)
    
    logger = setup_logging()
    logger.info(f"Statistics exported to {filename}")
    return True


def _export_csv(stats: Dict[str, Any], filename: str) -> bool:
    """Export statistics to CSV file (flattened)."""
    # Flatten nested dictionary
    flattened = _flatten_dict(stats)
    
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write header
        writer.writerow(['Metric', 'Value'])
        
        # Write data
        for key, value in flattened.items():
            writer.writerow([key, value])
    
    logger = setup_logging()
    logger.info(f"Statistics exported to {filename}")
    return True


def _flatten_dict(d: Dict[str, Any], parent_key: str = '', sep: str = '.') -> Dict[str, Any]:
    """Flatten nested dictionary."""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(_flatten_dict(v, new_key, sep=sep).items())
        elif isinstance(v, list):
            for i, item in enumerate(v):
                if isinstance(item, dict):
                    items.extend(_flatten_dict(item, f"{new_key}[{i}]", sep=sep).items())
                else:
                    items.append((f"{new_key}[{i}]", item))
        else:
            items.append((new_key, v))
    return dict(items)


class PacketLogger:
    """
    Logger for packet analysis results.
    """
    
    def __init__(self, log_file: str = "packet_analysis.log", 
                 log_format: str = "detailed"):
        """
        Initialize packet logger.
        
        Args:
            log_file (str): Log file path
            log_format (str): Log format ("detailed", "summary", "csv")
        """
        self.log_file = log_file
        self.log_format = log_format
        self.logger = setup_logging()
        
        # Create log file if it doesn't exist
        if not os.path.exists(log_file):
            with open(log_file, 'w', encoding='utf-8') as f:
                if log_format == "csv":
                    f.write("timestamp,src_ip,dst_ip,protocol,src_port,dst_port,size\n")
                else:
                    f.write(f"# Packet Analysis Log - Started {datetime.now()}\n")
    
    def log_packet(self, packet: Any) -> None:
        """
        Log a single packet.
        
        Args:
            packet: Packet to log
        """
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                if self.log_format == "csv":
                    self._log_csv_format(f, packet)
                elif self.log_format == "summary":
                    self._log_summary_format(f, packet)
                else:
                    self._log_detailed_format(f, packet)
        except Exception as e:
            self.logger.error(f"Failed to log packet: {str(e)}")
    
    def _log_csv_format(self, file_handle, packet: Any) -> None:
        """Log packet in CSV format."""
        timestamp = getattr(packet, 'time', time.time())
        src_ip = packet[IP].src if packet.haslayer(IP) else ""
        dst_ip = packet[IP].dst if packet.haslayer(IP) else ""
        protocol = get_protocol_name(packet)
        src_port = ""
        dst_port = ""
        
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        
        size = len(packet) if hasattr(packet, '__len__') else 0
        
        file_handle.write(f"{timestamp},{src_ip},{dst_ip},{protocol},{src_port},{dst_port},{size}\n")
    
    def _log_summary_format(self, file_handle, packet: Any) -> None:
        """Log packet in summary format."""
        timestamp = format_timestamp(getattr(packet, 'time', time.time()), "human")
        summary = packet.summary() if hasattr(packet, 'summary') else str(packet)
        file_handle.write(f"[{timestamp}] {summary}\n")
    
    def _log_detailed_format(self, file_handle, packet: Any) -> None:
        """Log packet in detailed format."""
        timestamp = format_timestamp(getattr(packet, 'time', time.time()), "human")
        file_handle.write(f"\n--- Packet at {timestamp} ---\n")
        
        # Basic info
        protocol = get_protocol_name(packet)
        size = len(packet) if hasattr(packet, '__len__') else 0
        file_handle.write(f"Protocol: {protocol}, Size: {size} bytes\n")
        
        # IP layer info
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            file_handle.write(f"IP: {ip_layer.src} -> {ip_layer.dst}\n")
        
        # Transport layer info
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            file_handle.write(f"TCP: {tcp_layer.sport} -> {tcp_layer.dport}, Flags: {tcp_layer.flags}\n")
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            file_handle.write(f"UDP: {udp_layer.sport} -> {udp_layer.dport}\n")
        
        # Packet summary
        summary = packet.summary() if hasattr(packet, 'summary') else str(packet)
        file_handle.write(f"Summary: {summary}\n")
    
    def log_analysis_results(self, results: Dict[str, Any]) -> None:
        """
        Log analysis results.
        
        Args:
            results (dict): Analysis results to log
        """
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(f"\n=== Analysis Results - {datetime.now()} ===\n")
                f.write(json.dumps(results, indent=2, default=str))
                f.write("\n")
        except Exception as e:
            self.logger.error(f"Failed to log analysis results: {str(e)}")


class Timer:
    """
    Simple timer context manager for performance measurement.
    """
    
    def __init__(self, description: str = "Operation"):
        """
        Initialize timer.
        
        Args:
            description (str): Description of the operation being timed
        """
        self.description = description
        self.start_time = None
        self.end_time = None
        self.logger = setup_logging()
    
    def __enter__(self):
        """Start the timer."""
        self.start_time = time.time()
        self.logger.info(f"Starting {self.description}")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Stop the timer and log the duration."""
        self.end_time = time.time()
        duration = self.end_time - self.start_time
        self.logger.info(f"{self.description} completed in {duration:.2f} seconds")
    
    def elapsed(self) -> float:
        """
        Get elapsed time.
        
        Returns:
            float: Elapsed time in seconds
        """
        if self.start_time is None:
            return 0.0
        
        current_time = self.end_time if self.end_time else time.time()
        return current_time - self.start_time


def create_report(packets: List[Any], output_file: str = "report.html") -> None:
    """
    Create an HTML report of packet analysis.
    
    Args:
        packets (List): Packets to analyze
        output_file (str): Output HTML file path
    
    Examples:
        >>> create_report(packets, "network_analysis_report.html")
    """
    from .analysis import analyze_packets
    
    # Analyze packets
    stats = analyze_packets(packets)
    
    # Generate HTML report
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Packet Analysis Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; }}
            .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
            .section {{ margin: 20px 0; }}
            .metric {{ background-color: #f9f9f9; padding: 10px; margin: 5px 0; border-left: 4px solid #007acc; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Packet Analysis Report</h1>
            <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Total packets analyzed: {len(packets)}</p>
        </div>
        
        <div class="section">
            <h2>Summary Statistics</h2>
            <div class="metric">
                <strong>Total Packets:</strong> {stats['summary']['total_packets']}
            </div>
            <div class="metric">
                <strong>Total Size:</strong> {stats['summary']['total_size_human']}
            </div>
            <div class="metric">
                <strong>Average Packet Size:</strong> {stats['summary']['average_packet_size']:.1f} bytes
            </div>
        </div>
        
        <div class="section">
            <h2>Protocol Distribution</h2>
            <table>
                <tr><th>Protocol</th><th>Count</th><th>Percentage</th></tr>
                {_generate_protocol_table(stats['protocols']['distribution'])}
            </table>
        </div>
        
        <div class="section">
            <h2>Top Source IPs</h2>
            <table>
                <tr><th>IP Address</th><th>Packet Count</th></tr>
                {_generate_ip_table(stats['ip_stats']['top_source_ips'])}
            </table>
        </div>
        
        <div class="section">
            <h2>Timing Information</h2>
            <div class="metric">
                <strong>Capture Duration:</strong> {stats['time_stats']['capture_duration']:.2f} seconds
            </div>
            <div class="metric">
                <strong>Packets per Second:</strong> {stats['time_stats']['packets_per_second']:.2f}
            </div>
        </div>
    </body>
    </html>
    """
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    logger = setup_logging()
    logger.info(f"HTML report generated: {output_file}")


def _generate_protocol_table(protocols: Dict[str, Any]) -> str:
    """Generate HTML table rows for protocol distribution."""
    rows = []
    for proto, stats in protocols.items():
        row = f"<tr><td>{proto}</td><td>{stats['count']}</td><td>{stats['percentage']:.1f}%</td></tr>"
        rows.append(row)
    return "\n".join(rows)


def _generate_ip_table(ip_list: List[tuple]) -> str:
    """Generate HTML table rows for IP statistics."""
    rows = []
    for ip, count in ip_list[:10]:  # Top 10
        row = f"<tr><td>{ip}</td><td>{count}</td></tr>"
        rows.append(row)
    return "\n".join(rows)


# Configuration management
class Config:
    """
    Configuration manager for PktAnalyzer.
    """
    
    def __init__(self):
        """Initialize configuration with defaults."""
        self.config = {
            'capture': {
                'default_interface': None,
                'default_timeout': 30,
                'buffer_size': 1000
            },
            'analysis': {
                'top_talkers_count': 10,
                'protocol_threshold': 5
            },
            'visualization': {
                'default_style': 'default',
                'figure_size': (10, 6),
                'dpi': 300
            },
            'logging': {
                'level': 'INFO',
                'format': 'detailed'
            }
        }
    
    def get(self, key: str, default=None):
        """Get configuration value using dot notation."""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any):
        """Set configuration value using dot notation."""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def save(self, filename: str):
        """Save configuration to file."""
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.config, f, indent=2)
    
    def load(self, filename: str):
        """Load configuration from file."""
        with open(filename, 'r', encoding='utf-8') as f:
            self.config.update(json.load(f))


# Global configuration instance
config = Config()


def get_system_info() -> Dict[str, Any]:
    """
    Get system information for debugging.
    
    Returns:
        Dict: System information
    """
    import platform
    import sys
    
    return {
        'python_version': sys.version,
        'platform': platform.platform(),
        'architecture': platform.architecture(),
        'processor': platform.processor(),
        'hostname': platform.node(),
        'timestamp': datetime.now().isoformat()
    }