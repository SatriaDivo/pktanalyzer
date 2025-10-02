"""
PktAnalyzer Capture Module

This module provides packet capture functionality using Scapy.
"""

import threading
import time
from typing import List, Optional, Callable, Any
import logging

try:
    from scapy.all import sniff, wrpcap, get_if_list, conf
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import ARP, Ether
except ImportError:
    raise ImportError("Scapy is required. Install with: pip install scapy")

from .utils import setup_logging, validate_filter


class PacketCapture:
    """
    Main packet capture class with support for live capture and file operations.
    """
    
    def __init__(self, interface: Optional[str] = None, verbose: bool = False):
        """
        Initialize packet capture.
        
        Args:
            interface (str, optional): Network interface to capture on
            verbose (bool): Enable verbose logging
        """
        self.interface = interface or conf.iface
        self.verbose = verbose
        self.logger = setup_logging(verbose)
        self.captured_packets = []
        self.is_capturing = False
        self._capture_thread = None
        self._stop_event = threading.Event()
        
    def get_available_interfaces(self) -> List[str]:
        """
        Get list of available network interfaces.
        
        Returns:
            List[str]: List of interface names
        """
        try:
            interfaces = get_if_list()
            self.logger.info(f"Available interfaces: {interfaces}")
            return interfaces
        except Exception as e:
            self.logger.error(f"Failed to get interfaces: {str(e)}")
            return []
    
    def capture_packets(self, count: int = 0, filter_expr: Optional[str] = None, 
                       interface: Optional[str] = None, timeout: Optional[int] = None,
                       callback: Optional[Callable] = None) -> List[Any]:
        """
        Capture network packets.
        
        Args:
            count (int): Number of packets to capture (0 = unlimited)
            filter_expr (str, optional): BPF filter expression
            interface (str, optional): Interface to capture on
            timeout (int, optional): Capture timeout in seconds
            callback (callable, optional): Callback function for each packet
        
        Returns:
            List: Captured packets
        
        Raises:
            ValueError: If filter expression is invalid
            RuntimeError: If capture fails
        """
        try:
            # Validate filter expression
            if filter_expr:
                if not validate_filter(filter_expr):
                    raise ValueError(f"Invalid filter expression: {filter_expr}")
            
            # Use provided interface or default
            iface = interface or self.interface
            
            # Validate interface
            available_interfaces = self.get_available_interfaces()
            if iface not in available_interfaces:
                self.logger.warning(f"Interface {iface} not found. Using default.")
                iface = conf.iface
            
            self.logger.info(f"Starting capture on {iface}")
            self.logger.info(f"Filter: {filter_expr or 'None'}")
            self.logger.info(f"Count: {count if count > 0 else 'Unlimited'}")
            
            # Internal packet handler
            def packet_handler(packet):
                if self.verbose:
                    self.logger.debug(f"Captured packet: {packet.summary()}")
                
                self.captured_packets.append(packet)
                
                # Call user callback if provided
                if callback:
                    try:
                        callback(packet)
                    except Exception as e:
                        self.logger.error(f"Callback error: {str(e)}")
            
            # Start capture
            self.is_capturing = True
            packets = sniff(
                iface=iface,
                filter=filter_expr,
                count=count,
                timeout=timeout,
                prn=packet_handler,
                store=True
            )
            
            self.is_capturing = False
            self.logger.info(f"Capture completed. Total packets: {len(packets)}")
            
            return packets
            
        except Exception as e:
            self.is_capturing = False
            self.logger.error(f"Capture failed: {str(e)}")
            raise RuntimeError(f"Failed to capture packets: {str(e)}")
    
    def start_live_capture(self, filter_expr: Optional[str] = None,
                          interface: Optional[str] = None,
                          callback: Optional[Callable] = None) -> threading.Thread:
        """
        Start live packet capture in a separate thread.
        
        Args:
            filter_expr (str, optional): BPF filter expression
            interface (str, optional): Interface to capture on
            callback (callable, optional): Callback function for each packet
        
        Returns:
            threading.Thread: The capture thread
        
        Raises:
            RuntimeError: If capture is already running
        """
        if self.is_capturing:
            raise RuntimeError("Capture is already running")
        
        def capture_worker():
            try:
                self.capture_packets(
                    count=0,  # Unlimited
                    filter_expr=filter_expr,
                    interface=interface,
                    callback=callback
                )
            except Exception as e:
                self.logger.error(f"Live capture error: {str(e)}")
        
        self._stop_event.clear()
        self._capture_thread = threading.Thread(target=capture_worker, daemon=True)
        self._capture_thread.start()
        
        self.logger.info("Live capture started")
        return self._capture_thread
    
    def stop_capture(self):
        """Stop the live capture."""
        if self.is_capturing:
            self._stop_event.set()
            self.is_capturing = False
            self.logger.info("Capture stopped")
    
    def save_pcap(self, packets: List[Any], filename: str) -> bool:
        """
        Save packets to PCAP file.
        
        Args:
            packets (List): Packets to save
            filename (str): Output filename
        
        Returns:
            bool: True if successful
        
        Raises:
            ValueError: If no packets to save
            IOError: If file operations fail
        """
        try:
            if not packets:
                raise ValueError("No packets to save")
            
            wrpcap(filename, packets)
            self.logger.info(f"Saved {len(packets)} packets to {filename}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save PCAP: {str(e)}")
            raise IOError(f"Failed to save PCAP file: {str(e)}")
    
    def get_captured_packets(self) -> List[Any]:
        """
        Get all captured packets from current session.
        
        Returns:
            List: All captured packets
        """
        return self.captured_packets.copy()
    
    def clear_captured_packets(self):
        """Clear the captured packets buffer."""
        self.captured_packets.clear()
        self.logger.info("Captured packets buffer cleared")
    
    def get_capture_stats(self) -> dict:
        """
        Get capture statistics.
        
        Returns:
            dict: Capture statistics
        """
        return {
            'total_packets': len(self.captured_packets),
            'is_capturing': self.is_capturing,
            'interface': self.interface,
            'capture_active': self._capture_thread is not None and self._capture_thread.is_alive()
        }


def capture_packets(count: int = 0, filter_expr: Optional[str] = None, 
                   interface: Optional[str] = None, timeout: Optional[int] = None,
                   verbose: bool = False) -> List[Any]:
    """
    Simple function to capture packets (convenience wrapper).
    
    Args:
        count (int): Number of packets to capture (0 = unlimited)
        filter_expr (str, optional): BPF filter expression
        interface (str, optional): Interface to capture on
        timeout (int, optional): Capture timeout in seconds
        verbose (bool): Enable verbose logging
    
    Returns:
        List: Captured packets
    
    Examples:
        >>> # Capture 10 TCP packets
        >>> packets = capture_packets(count=10, filter_expr="tcp")
        
        >>> # Capture HTTP traffic for 30 seconds
        >>> packets = capture_packets(filter_expr="port 80", timeout=30)
        
        >>> # Capture all traffic on specific interface
        >>> packets = capture_packets(interface="eth0")
    """
    capturer = PacketCapture(interface=interface, verbose=verbose)
    return capturer.capture_packets(
        count=count,
        filter_expr=filter_expr,
        interface=interface,
        timeout=timeout
    )


def save_pcap(packets: List[Any], filename: str = "capture.pcap") -> bool:
    """
    Save packets to PCAP file (convenience wrapper).
    
    Args:
        packets (List): Packets to save
        filename (str): Output filename
    
    Returns:
        bool: True if successful
    
    Examples:
        >>> packets = capture_packets(count=100)
        >>> save_pcap(packets, "my_capture.pcap")
    """
    capturer = PacketCapture()
    return capturer.save_pcap(packets, filename)


class AsyncPacketCapture:
    """
    Asynchronous packet capture with callback support.
    """
    
    def __init__(self, callback: Callable, interface: Optional[str] = None):
        """
        Initialize async capture.
        
        Args:
            callback (callable): Function to call for each packet
            interface (str, optional): Network interface
        """
        self.callback = callback
        self.interface = interface
        self.capturer = PacketCapture(interface=interface)
        self.logger = setup_logging()
    
    def start(self, filter_expr: Optional[str] = None) -> threading.Thread:
        """
        Start asynchronous capture.
        
        Args:
            filter_expr (str, optional): BPF filter expression
        
        Returns:
            threading.Thread: The capture thread
        """
        return self.capturer.start_live_capture(
            filter_expr=filter_expr,
            interface=self.interface,
            callback=self.callback
        )
    
    def stop(self):
        """Stop the capture."""
        self.capturer.stop_capture()


# Predefined common filters
COMMON_FILTERS = {
    'tcp': 'tcp',
    'udp': 'udp', 
    'icmp': 'icmp',
    'arp': 'arp',
    'dns': 'port 53',
    'http': 'port 80',
    'https': 'port 443',
    'ssh': 'port 22',
    'ftp': 'port 21',
    'telnet': 'port 23',
    'smtp': 'port 25',
    'pop3': 'port 110',
    'imap': 'port 143',
    'snmp': 'port 161',
    'broadcast': 'broadcast',
    'multicast': 'multicast'
}


def get_common_filter(name: str) -> Optional[str]:
    """
    Get a common filter expression by name.
    
    Args:
        name (str): Filter name
    
    Returns:
        str or None: Filter expression
    
    Examples:
        >>> filter_expr = get_common_filter('http')
        >>> packets = capture_packets(filter_expr=filter_expr)
    """
    return COMMON_FILTERS.get(name.lower())


def list_common_filters() -> List[str]:
    """
    List available common filter names.
    
    Returns:
        List[str]: Available filter names
    """
    return list(COMMON_FILTERS.keys())