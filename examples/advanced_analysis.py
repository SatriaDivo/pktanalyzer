"""
Advanced Filtering and Analysis Example

This example demonstrates advanced packet filtering capabilities
and detailed analysis features of PktAnalyzer.
"""

import sys
import os

# Add parent directory to path to import pktanalyzer
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def advanced_filtering_example():
    """Demonstrate advanced filtering capabilities."""
    try:
        from pktanalyzer import (
            capture_packets,
            PacketFilter,
            filter_by_ip,
            filter_by_port,
            filter_conversations,
            apply_preset_filter,
            list_filter_presets,
            setup_logging
        )
        
        print("🔧 Advanced Filtering Example")
        print("=" * 50)
        
        # Setup logging
        logger = setup_logging(level='INFO')
        
        print("1. Capturing packets for filtering...")
        
        # Capture a larger set of packets
        packets = capture_packets(
            count=200,
            timeout=60,
            filter_str="ip"
        )
        
        if not packets:
            print("❌ No packets captured")
            return
        
        print(f"✅ Captured {len(packets)} packets")
        
        # Initialize packet filter
        pf = PacketFilter()
        
        print("\n2. Basic filtering operations:")
        
        # Filter by specific IP
        if packets:
            # Get first IP from packets for demo
            from scapy.all import IP
            first_ip = None
            for pkt in packets:
                if IP in pkt:
                    first_ip = pkt[IP].src
                    break
            
            if first_ip:
                ip_filtered = filter_by_ip(packets, first_ip)
                print(f"   Packets from/to {first_ip}: {len(ip_filtered)}")
        
        # Filter by protocol
        tcp_packets = pf.filter_by_protocol(packets, 'TCP')
        udp_packets = pf.filter_by_protocol(packets, 'UDP')
        icmp_packets = pf.filter_by_protocol(packets, 'ICMP')
        
        print(f"   TCP packets: {len(tcp_packets)}")
        print(f"   UDP packets: {len(udp_packets)}")
        print(f"   ICMP packets: {len(icmp_packets)}")
        
        # Filter by common ports
        web_traffic = filter_by_port(packets, [80, 443])
        dns_traffic = filter_by_port(packets, 53)
        
        print(f"   Web traffic (80,443): {len(web_traffic)}")
        print(f"   DNS traffic (53): {len(dns_traffic)}")
        
        print("\n3. Advanced filtering:")
        
        # Filter by packet size
        large_packets = pf.filter_by_size(packets, min_size=1000)
        small_packets = pf.filter_by_size(packets, max_size=100)
        
        print(f"   Large packets (>1000 bytes): {len(large_packets)}")
        print(f"   Small packets (<100 bytes): {len(small_packets)}")
        
        # Filter conversations
        conversations = filter_conversations(packets, min_packets=5)
        print(f"   Active conversations (>5 packets): {len(conversations)}")
        
        print("\n4. Preset filters:")
        
        # List available presets
        presets = list_filter_presets()
        print(f"   Available presets: {', '.join(presets)}")
        
        # Apply preset filters
        for preset in ['web_traffic', 'dns_traffic', 'security_events']:
            if preset in presets:
                filtered = apply_preset_filter(packets, preset)
                print(f"   {preset}: {len(filtered)} packets")
        
        print("\n5. Custom complex filtering:")
        
        # Create custom filter with multiple conditions
        custom_filter = {
            'protocols': ['TCP'],
            'ports': [80, 443, 8080],
            'size_range': (100, 1500),
            'flags': ['SYN', 'ACK']
        }
        
        custom_filtered = pf.advanced_filter(packets, **custom_filter)
        print(f"   Custom filter result: {len(custom_filtered)} packets")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")

def detailed_analysis_example():
    """Demonstrate detailed packet analysis."""
    try:
        from pktanalyzer import (
            capture_packets,
            PacketAnalyzer,
            analyze_packets,
            get_protocol_stats,
            get_top_talkers,
            detect_anomalies,
            summarize_packet
        )
        
        print("\n" + "="*50)
        print("📊 Detailed Analysis Example")
        print("=" * 50)
        
        print("Capturing packets for detailed analysis...")
        
        packets = capture_packets(
            count=150,
            timeout=45,
            filter_str="ip"
        )
        
        if not packets:
            print("❌ No packets captured")
            return
        
        print(f"✅ Captured {len(packets)} packets")
        
        # Initialize analyzer
        analyzer = PacketAnalyzer()
        
        print("\n1. Protocol statistics:")
        
        # Get detailed protocol stats
        proto_stats = get_protocol_stats(packets)
        for protocol, stats in proto_stats.items():
            print(f"   {protocol}:")
            print(f"     Packets: {stats['count']}")
            print(f"     Bytes: {stats['bytes']}")
            print(f"     Avg size: {stats['avg_size']:.1f}")
        
        print("\n2. Traffic analysis:")
        
        # Analyze traffic patterns
        analysis = analyze_packets(packets)
        
        print(f"   Total packets: {analysis['total_packets']}")
        print(f"   Total bytes: {analysis['total_bytes']}")
        print(f"   Average packet size: {analysis['avg_packet_size']:.1f}")
        print(f"   Unique source IPs: {len(analysis['unique_ips'])}")
        
        # Time-based analysis
        if 'time_stats' in analysis:
            time_stats = analysis['time_stats']
            print(f"   Duration: {time_stats['duration']:.2f} seconds")
            print(f"   Packets per second: {time_stats['pps']:.2f}")
        
        print("\n3. Top talkers:")
        
        # Get top talking hosts
        top_talkers = get_top_talkers(packets, top_n=10)
        for i, (ip, count) in enumerate(top_talkers[:5]):
            print(f"   {i+1}. {ip}: {count} packets")
        
        print("\n4. Anomaly detection:")
        
        # Detect traffic anomalies
        anomalies = detect_anomalies(packets)
        if anomalies:
            print(f"   Detected {len(anomalies)} anomalies:")
            for anomaly in anomalies[:3]:  # Show first 3
                print(f"     - {anomaly}")
        else:
            print("   No anomalies detected")
        
        print("\n5. Individual packet analysis:")
        
        # Analyze individual packets
        for i, packet in enumerate(packets[:3]):  # Analyze first 3 packets
            summary = summarize_packet(packet)
            print(f"   Packet {i+1}: {summary}")
        
        print("\n6. Bandwidth analysis:")
        
        # Calculate bandwidth usage
        bandwidth = analyzer.calculate_bandwidth(packets)
        print(f"   Peak bandwidth: {bandwidth['peak']:.2f} Mbps")
        print(f"   Average bandwidth: {bandwidth['average']:.2f} Mbps")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")

def visualization_example():
    """Demonstrate advanced visualization features."""
    try:
        from pktanalyzer import (
            capture_packets,
            PacketVisualizer,
            plot_protocol_distribution,
            plot_traffic_over_time,
            create_analysis_dashboard,
            save_all_plots,
            quick_visualize
        )
        
        print("\n" + "="*50)
        print("📈 Visualization Example")
        print("=" * 50)
        
        print("Capturing packets for visualization...")
        
        packets = capture_packets(
            count=100,
            timeout=30,
            filter_str="ip"
        )
        
        if not packets:
            print("❌ No packets captured")
            return
        
        print(f"✅ Captured {len(packets)} packets")
        
        # Initialize visualizer
        viz = PacketVisualizer()
        
        print("\n1. Creating individual plots:")
        
        # Protocol distribution pie chart
        plot_protocol_distribution(
            packets, 
            chart_type='pie',
            save_path='advanced_protocol_pie.png'
        )
        print("   ✅ Protocol pie chart saved")
        
        # Traffic over time line chart
        plot_traffic_over_time(
            packets,
            interval='1s',
            save_path='advanced_traffic_time.png'
        )
        print("   ✅ Traffic timeline saved")
        
        print("\n2. Creating comprehensive dashboard:")
        
        # Create full analysis dashboard
        create_analysis_dashboard(
            packets,
            save_path='advanced_dashboard.png',
            include_security=True
        )
        print("   ✅ Analysis dashboard saved")
        
        print("\n3. Quick visualization:")
        
        # Quick visualization for rapid analysis
        quick_visualize(packets, output_dir='advanced_plots')
        print("   ✅ Quick plots saved to 'advanced_plots' directory")
        
        print("\n4. Custom visualizations:")
        
        # Create custom visualizations
        viz.plot_packet_sizes(packets, save_path='packet_sizes.png')
        viz.plot_port_usage(packets, save_path='port_usage.png')
        viz.plot_ip_geolocation(packets, save_path='ip_geo.png')
        
        print("   ✅ Custom visualizations created")
        
        print("\n5. Saving all plots:")
        
        # Save all available plots
        save_all_plots(packets, output_dir='all_advanced_plots')
        print("   ✅ All plots saved to 'all_advanced_plots' directory")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")

def main():
    """Run advanced examples."""
    print("🔧 PktAnalyzer Advanced Examples")
    print("=" * 60)
    print("This script demonstrates advanced features of PktAnalyzer")
    print()
    
    try:
        advanced_filtering_example()
        detailed_analysis_example()
        visualization_example()
        
        print("\n" + "="*60)
        print("✅ Advanced examples completed!")
        print("\nGenerated files:")
        print("- advanced_protocol_pie.png")
        print("- advanced_traffic_time.png")
        print("- advanced_dashboard.png")
        print("- advanced_plots/ directory")
        print("- all_advanced_plots/ directory")
        print("\nNext steps:")
        print("1. Examine the generated visualization files")
        print("2. Experiment with different filter combinations")
        print("3. Try with larger packet captures")
        print("4. Customize analysis parameters")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Advanced examples interrupted by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")

if __name__ == "__main__":
    main()