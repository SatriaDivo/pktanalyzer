#!/usr/bin/env python3
"""
PCAP File Analysis Example

This example demonstrates how to analyze existing PCAP files using PktAnalyzer.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def main():
    """PCAP file analysis example."""
    try:
        from pktanalyzer import (
            load_pcap, 
            analyze_packets, 
            filter_by_protocol,
            filter_by_ip,
            export_stats,
            plot_protocol_distribution
        )
        
        print("📁 PCAP File Analysis Example")
        print("=" * 40)
        
        # Sample PCAP file (you can replace this with your own)
        pcap_file = "sample_traffic.pcap"
        
        # For demonstration, let's create a small sample if file doesn't exist
        if not os.path.exists(pcap_file):
            print(f"ℹ️  PCAP file '{pcap_file}' not found")
            print("   Creating sample data by capturing live traffic...")
            
            # Capture some sample data
            from pktanalyzer import capture_packets, save_pcap
            
            print("   Capturing 30 packets for demo...")
            sample_packets = capture_packets(count=30, timeout=60, filter_str="ip")
            
            if sample_packets:
                save_pcap(sample_packets, pcap_file)
                print(f"   ✅ Sample PCAP saved as '{pcap_file}'")
            else:
                print("   ❌ Could not capture sample data")
                print("   Please provide your own PCAP file or check network connectivity")
                return
        
        print(f"\n1. Loading PCAP file: {pcap_file}")
        packets = load_pcap(pcap_file)
        
        if not packets:
            print("❌ No packets loaded from file")
            return
        
        print(f"✅ Loaded {len(packets)} packets")
        
        print(f"\n2. Performing analysis...")
        stats = analyze_packets(packets)
        
        print(f"   Basic Statistics:")
        print(f"   - Total packets: {stats['total_packets']}")
        print(f"   - Total size: {stats['total_bytes']:,} bytes")
        print(f"   - Average packet size: {stats['avg_packet_size']:.1f} bytes")
        print(f"   - Unique IPs: {len(stats['unique_ips'])}")
        
        print(f"\n3. Protocol Distribution:")
        for protocol, data in stats['protocol_distribution'].items():
            count = data['count']
            percentage = data['percentage']
            print(f"   - {protocol}: {count} packets ({percentage:.1f}%)")
        
        print(f"\n4. Top Talkers (Source IPs):")
        for i, (ip, count) in enumerate(stats['top_talkers'][:5]):
            print(f"   {i+1}. {ip}: {count} packets")
        
        print(f"\n5. Applying filters...")
        
        # Filter TCP packets
        tcp_packets = filter_by_protocol(packets, 'TCP')
        print(f"   TCP packets: {len(tcp_packets)}")
        
        # Filter UDP packets  
        udp_packets = filter_by_protocol(packets, 'UDP')
        print(f"   UDP packets: {len(udp_packets)}")
        
        # Filter by specific IP (if any)
        if stats['unique_ips']:
            sample_ip = list(stats['unique_ips'])[0]
            ip_packets = filter_by_ip(packets, sample_ip)
            print(f"   Packets from/to {sample_ip}: {len(ip_packets)}")
        
        print(f"\n6. Creating visualizations...")
        
        # Create protocol distribution chart
        chart_file = "pcap_protocol_distribution.png"
        plot_protocol_distribution(packets, save_path=chart_file)
        print(f"   ✅ Protocol chart saved: {chart_file}")
        
        print(f"\n7. Exporting analysis results...")
        
        # Export to JSON
        json_file = "pcap_analysis.json"
        export_stats(stats, json_file, format='json')
        print(f"   ✅ JSON report saved: {json_file}")
        
        # Export to CSV
        csv_file = "pcap_analysis.csv"
        export_stats(stats, csv_file, format='csv')
        print(f"   ✅ CSV report saved: {csv_file}")
        
        print(f"\n✅ PCAP analysis completed!")
        print("   Files generated:")
        print(f"   - {chart_file} (visualization)")
        print(f"   - {json_file} (detailed stats)")
        print(f"   - {csv_file} (summary data)")
        print("\n   Next: Try live_monitor.py for real-time analysis")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("   Make sure to install dependencies:")
        print("   pip install scapy matplotlib numpy")
    except FileNotFoundError as e:
        print(f"❌ File error: {e}")
        print("   Make sure the PCAP file exists and is readable")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()