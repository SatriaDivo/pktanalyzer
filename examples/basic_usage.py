"""
Basic Packet Capture Example

This example demonstrates how to use PktAnalyzer for basic packet capture
and analysis operations.
"""

import sys
import os

# Add parent directory to path to import pktanalyzer
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def basic_capture_example():
    """Demonstrate basic packet capture functionality."""
    try:
        from pktanalyzer import (
            capture_packets, 
            analyze_packets, 
            plot_protocol_distribution,
            setup_logging
        )
        
        print("🔍 PktAnalyzer - Basic Capture Example")
        print("=" * 50)
        
        # Setup logging
        logger = setup_logging(level='INFO')
        
        print("1. Capturing packets...")
        print("   Note: This requires admin/root privileges")
        print("   Capturing 50 packets from any interface...")
        
        # Capture packets (requires admin privileges)
        packets = capture_packets(
            interface=None,  # Use default interface
            count=50,
            timeout=30,
            filter_str="ip"  # Only IP packets
        )
        
        if not packets:
            print("❌ No packets captured. Make sure you have admin privileges.")
            return
        
        print(f"✅ Captured {len(packets)} packets")
        
        print("\n2. Analyzing packets...")
        
        # Analyze captured packets
        stats = analyze_packets(packets)
        
        print(f"   Total packets: {stats['total_packets']}")
        print(f"   Unique IPs: {len(stats['unique_ips'])}")
        print(f"   Protocol distribution:")
        for protocol, count in stats['protocol_distribution'].items():
            print(f"     - {protocol}: {count}")
        
        print("\n3. Creating visualization...")
        
        # Create protocol distribution chart
        plot_protocol_distribution(packets, save_path="protocol_dist.png")
        print("   ✅ Protocol distribution chart saved as 'protocol_dist.png'")
        
        print("\n4. Top talkers:")
        for i, (ip, count) in enumerate(stats['top_talkers'][:5]):
            print(f"   {i+1}. {ip}: {count} packets")
            
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("   Make sure to install required dependencies:")
        print("   pip install scapy matplotlib numpy")
    except Exception as e:
        print(f"❌ Error: {e}")
        print("   Note: Packet capture requires admin/root privileges")

def file_analysis_example():
    """Demonstrate analysis of PCAP files."""
    try:
        from pktanalyzer import (
            load_pcap,
            analyze_packets,
            filter_by_protocol,
            create_analysis_dashboard
        )
        
        print("\n" + "="*50)
        print("📁 File Analysis Example")
        print("=" * 50)
        
        # This example would work if you have a PCAP file
        pcap_file = "sample.pcap"  # Replace with actual file path
        
        if not os.path.exists(pcap_file):
            print(f"ℹ️  PCAP file '{pcap_file}' not found.")
            print("   To use this example:")
            print("   1. Place a .pcap file in this directory")
            print("   2. Update the 'pcap_file' variable with the filename")
            return
        
        print(f"Loading packets from {pcap_file}...")
        packets = load_pcap(pcap_file)
        
        if not packets:
            print("❌ No packets loaded from file")
            return
        
        print(f"✅ Loaded {len(packets)} packets")
        
        # Filter TCP packets
        tcp_packets = filter_by_protocol(packets, 'TCP')
        print(f"   TCP packets: {len(tcp_packets)}")
        
        # Analyze all packets
        stats = analyze_packets(packets)
        print(f"   Total data: {stats['total_bytes']} bytes")
        
        # Create dashboard
        dashboard_path = "analysis_dashboard.png"
        create_analysis_dashboard(packets, save_path=dashboard_path)
        print(f"   ✅ Dashboard saved as '{dashboard_path}'")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")

def security_analysis_example():
    """Demonstrate security analysis features."""
    try:
        from pktanalyzer import (
            capture_packets,
            SecurityAnalyzer,
            filter_by_protocol
        )
        
        print("\n" + "="*50)
        print("🔒 Security Analysis Example")
        print("=" * 50)
        
        print("Capturing packets for security analysis...")
        
        # Capture packets for security analysis
        packets = capture_packets(
            count=100,
            timeout=60,
            filter_str="tcp or udp or icmp"
        )
        
        if not packets:
            print("❌ No packets captured for security analysis")
            return
        
        print(f"✅ Captured {len(packets)} packets for analysis")
        
        # Initialize security analyzer
        security = SecurityAnalyzer()
        
        # Detect potential SYN flood
        syn_flood = security.detect_syn_flood(packets, threshold=10)
        if syn_flood['detected']:
            print("⚠️  Potential SYN flood detected!")
            print(f"   Attack rate: {syn_flood['rate']:.2f} SYN/sec")
        else:
            print("✅ No SYN flood detected")
        
        # Detect port scans
        port_scan = security.detect_port_scan(packets, threshold=5)
        if port_scan['detected']:
            print("⚠️  Potential port scan detected!")
            print(f"   Scanner IP: {port_scan['scanner_ip']}")
            print(f"   Ports scanned: {len(port_scan['ports'])}")
        else:
            print("✅ No port scan detected")
        
        # Check for suspicious activity
        suspicious = security.detect_suspicious_activity(packets)
        if suspicious:
            print("⚠️  Suspicious activities detected:")
            for activity in suspicious:
                print(f"   - {activity}")
        else:
            print("✅ No suspicious activity detected")
            
    except ImportError as e:
        print(f"❌ Import error: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")

def main():
    """Run all examples."""
    print("🔍 PktAnalyzer Examples")
    print("=" * 60)
    print("This script demonstrates basic usage of PktAnalyzer library")
    print()
    
    # Check if running as admin (required for packet capture)
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if not is_admin:
            print("⚠️  Warning: Not running as administrator")
            print("   Some features may not work without admin privileges")
            print()
    except:
        print("ℹ️  Admin check not available on this system")
        print()
    
    # Run examples
    try:
        basic_capture_example()
        file_analysis_example()
        security_analysis_example()
        
        print("\n" + "="*60)
        print("✅ Examples completed!")
        print("\nNext steps:")
        print("1. Check generated visualization files")
        print("2. Try with your own PCAP files")
        print("3. Explore advanced filtering options")
        print("4. Check other example scripts")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Examples interrupted by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")

if __name__ == "__main__":
    main()