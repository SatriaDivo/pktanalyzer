"""
PktAnalyzer - A comprehensive packet capture and analysis library

This library provides tools for network packet capture, analysis, filtering,
and visualization using Scapy as the core engine.

Author: PktAnalyzer Development Team
Version: 1.0.0
License: MIT
"""

__version__ = "1.0.0"
__author__ = "PktAnalyzer Development Team"
__license__ = "MIT"

# Core imports
from .capture import (
    PacketCapture,
    AsyncPacketCapture,
    capture_packets,
    save_pcap,
    get_common_filter,
    list_common_filters,
    COMMON_FILTERS
)

from .analysis import (
    PacketAnalyzer,
    SecurityAnalyzer,
    analyze_packets,
    summarize_packet,
    get_protocol_stats,
    get_top_talkers,
    detect_anomalies
)

from .filters import (
    PacketFilter,
    filter_by_ip,
    filter_by_protocol,
    filter_by_port,
    get_unique_ips,
    get_unique_ports,
    filter_conversations,
    apply_preset_filter,
    list_filter_presets,
    FILTER_PRESETS
)

from .visualization import (
    PacketVisualizer,
    plot_protocol_distribution,
    plot_traffic_over_time,
    create_analysis_dashboard,
    save_all_plots,
    quick_visualize,
    VISUALIZATION_PRESETS
)

from .utils import (
    setup_logging,
    get_protocol_name,
    format_bytes,
    format_timestamp,
    validate_filter,
    load_pcap,
    export_stats,
    PacketLogger,
    Timer,
    create_report,
    Config,
    config,
    get_system_info
)

# Define what gets imported with "from pktanalyzer import *"
__all__ = [
    # Core classes
    'PacketCapture',
    'AsyncPacketCapture',
    'PacketAnalyzer',
    'SecurityAnalyzer',
    'PacketFilter',
    'PacketVisualizer',
    'PacketLogger',
    'Timer',
    'Config',
    
    # Capture functions
    'capture_packets',
    'save_pcap',
    'get_common_filter',
    'list_common_filters',
    
    # Analysis functions
    'analyze_packets',
    'summarize_packet',
    'get_protocol_stats',
    'get_top_talkers',
    'detect_anomalies',
    
    # Filter functions
    'filter_by_ip',
    'filter_by_protocol',
    'filter_by_port',
    'get_unique_ips',
    'get_unique_ports',
    'filter_conversations',
    'apply_preset_filter',
    'list_filter_presets',
    
    # Visualization functions
    'plot_protocol_distribution',
    'plot_traffic_over_time',
    'create_analysis_dashboard',
    'save_all_plots',
    'quick_visualize',
    
    # Utility functions
    'setup_logging',
    'get_protocol_name',
    'format_bytes',
    'format_timestamp',
    'validate_filter',
    'load_pcap',
    'export_stats',
    'create_report',
    'get_system_info',
    
    # Constants
    'COMMON_FILTERS',
    'FILTER_PRESETS',
    'VISUALIZATION_PRESETS',
    'config',
    
    # Metadata
    '__version__',
    '__author__',
    '__license__'
]

# Setup default logging
import logging
logger = setup_logging()

def get_version():
    """Get the current version of PktAnalyzer."""
    return __version__

def get_info():
    """Get library information."""
    return {
        'name': 'PktAnalyzer',
        'version': __version__,
        'author': __author__,
        'license': __license__,
        'description': 'A comprehensive packet capture and analysis library'
    }

def check_dependencies():
    """
    Check if all required dependencies are available.
    
    Returns:
        Dict: Dependency status
    """
    dependencies = {
        'scapy': False,
        'matplotlib': False,
        'numpy': False
    }
    
    try:
        import scapy
        dependencies['scapy'] = True
    except ImportError:
        pass
    
    try:
        import matplotlib
        dependencies['matplotlib'] = True
    except ImportError:
        pass
    
    try:
        import numpy
        dependencies['numpy'] = True
    except ImportError:
        pass
    
    return dependencies

def print_welcome():
    """Print welcome message with basic info."""
    deps = check_dependencies()
    missing_deps = [dep for dep, available in deps.items() if not available]
    
    print(f"🔍 PktAnalyzer v{__version__} - Network Packet Analysis Library")
    print("=" * 60)
    
    if missing_deps:
        print("⚠️  Missing dependencies:")
        for dep in missing_deps:
            print(f"   - {dep}")
        print("\nInstall with: pip install scapy matplotlib numpy")
    else:
        print("✅ All dependencies available")
    
    print("\nQuick start:")
    print("  from pktanalyzer import capture_packets, analyze_packets")
    print("  packets = capture_packets(count=100)")
    print("  stats = analyze_packets(packets)")
    print("\nFor examples, check the examples/ directory")
    print("=" * 60)

# Initialize library
logger.info(f"PktAnalyzer v{__version__} initialized")

# Print welcome message if in interactive mode
import sys
if hasattr(sys, 'ps1'):  # Interactive mode
    print_welcome()