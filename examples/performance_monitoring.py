"""
Performance Monitoring Example

This example demonstrates how to use PktAnalyzer for network performance
monitoring, bandwidth analysis, and quality of service (QoS) assessment.
"""

import sys
import os
import time

# Add parent directory to path to import pktanalyzer
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def network_performance_monitoring():
    """Demonstrate network performance monitoring capabilities."""
    try:
        from pktanalyzer import (
            capture_packets,
            PacketAnalyzer,
            analyze_packets,
            plot_traffic_over_time,
            Timer,
            setup_logging
        )
        
        print("📊 Network Performance Monitoring")
        print("=" * 50)
        
        # Setup performance logging
        logger = setup_logging(level='INFO', log_file='performance_monitor.log')
        
        print("1. Capturing traffic for performance analysis...")
        
        # Use Timer for performance measurement
        with Timer() as capture_timer:
            packets = capture_packets(
                count=500,
                timeout=180,  # 3 minutes
                filter_str="ip"
            )
        
        if not packets:
            print("❌ No packets captured")
            return
        
        print(f"✅ Captured {len(packets)} packets in {capture_timer.elapsed:.2f}s")
        
        # Initialize analyzer
        analyzer = PacketAnalyzer()
        
        print("\n2. Bandwidth analysis:")
        
        # Calculate bandwidth metrics
        bandwidth = analyzer.calculate_bandwidth(packets)
        print(f"   Peak bandwidth: {bandwidth['peak']:.2f} Mbps")
        print(f"   Average bandwidth: {bandwidth['average']:.2f} Mbps")
        print(f"   95th percentile: {bandwidth['percentile_95']:.2f} Mbps")
        print(f"   Bandwidth utilization: {bandwidth['utilization']:.1f}%")
        
        print("\n3. Latency analysis:")
        
        # Analyze network latency
        latency = analyzer.analyze_latency(packets)
        if latency:
            print(f"   Average RTT: {latency['avg_rtt']:.2f} ms")
            print(f"   Minimum RTT: {latency['min_rtt']:.2f} ms")
            print(f"   Maximum RTT: {latency['max_rtt']:.2f} ms")
            print(f"   Jitter: {latency['jitter']:.2f} ms")
        else:
            print("   ⚠️  Insufficient data for latency analysis")
        
        print("\n4. Throughput analysis:")
        
        # Calculate throughput metrics
        throughput = analyzer.calculate_throughput(packets)
        print(f"   Packets per second: {throughput['pps']:.2f}")
        print(f"   Bytes per second: {throughput['bps']:.0f}")
        print(f"   Peak throughput: {throughput['peak_pps']:.2f} pps")
        
        print("\n5. Protocol performance:")
        
        # Analyze performance by protocol
        protocol_perf = analyzer.analyze_protocol_performance(packets)
        for protocol, metrics in protocol_perf.items():
            print(f"   {protocol}:")
            print(f"     Avg size: {metrics['avg_size']:.1f} bytes")
            print(f"     Throughput: {metrics['throughput']:.2f} Mbps")
            
        print("\n6. Quality of Service (QoS) analysis:")
        
        # Analyze QoS metrics
        qos = analyzer.analyze_qos(packets)
        print(f"   Packet loss rate: {qos['packet_loss_rate']:.2f}%")
        print(f"   Out-of-order packets: {qos['out_of_order']}")
        print(f"   Duplicate packets: {qos['duplicates']}")
        
        print("\n7. Creating performance visualization:")
        
        # Create traffic timeline
        plot_traffic_over_time(
            packets,
            interval='10s',
            save_path='performance_timeline.png'
        )
        print("   ✅ Performance timeline saved")
        
        # Generate performance report
        performance_report = {
            'capture_duration': capture_timer.elapsed,
            'bandwidth': bandwidth,
            'latency': latency,
            'throughput': throughput,
            'qos': qos,
            'protocol_performance': protocol_perf
        }
        
        print(f"\n📈 Performance Summary:")
        print(f"   Overall health: {'Good' if qos['packet_loss_rate'] < 1 else 'Needs attention'}")
        print(f"   Network utilization: {bandwidth['utilization']:.1f}%")
        print(f"   Quality score: {qos.get('quality_score', 'N/A')}")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")

def bandwidth_monitoring():
    """Demonstrate bandwidth monitoring and analysis."""
    try:
        from pktanalyzer import (
            capture_packets,
            PacketAnalyzer,
            filter_by_protocol,
            plot_protocol_distribution,
            format_bytes
        )
        
        print("\n" + "="*50)
        print("📡 Bandwidth Monitoring")
        print("=" * 50)
        
        print("Monitoring bandwidth usage...")
        
        # Capture packets for bandwidth analysis
        packets = capture_packets(
            count=300,
            timeout=120,
            filter_str="ip"
        )
        
        if not packets:
            print("❌ No packets captured")
            return
        
        print(f"✅ Captured {len(packets)} packets")
        
        analyzer = PacketAnalyzer()
        
        print("\n1. Overall bandwidth usage:")
        
        # Calculate total bandwidth
        total_stats = analyzer.calculate_total_bandwidth(packets)
        print(f"   Total data transferred: {format_bytes(total_stats['total_bytes'])}")
        print(f"   Upload: {format_bytes(total_stats['upload_bytes'])}")
        print(f"   Download: {format_bytes(total_stats['download_bytes'])}")
        print(f"   Ratio (Up/Down): {total_stats['upload_ratio']:.2f}")
        
        print("\n2. Bandwidth by protocol:")
        
        # Analyze bandwidth per protocol
        protocols = ['TCP', 'UDP', 'ICMP']
        protocol_bandwidth = {}
        
        for protocol in protocols:
            proto_packets = filter_by_protocol(packets, protocol)
            if proto_packets:
                proto_stats = analyzer.calculate_protocol_bandwidth(proto_packets)
                protocol_bandwidth[protocol] = proto_stats
                print(f"   {protocol}: {format_bytes(proto_stats['bytes'])} "
                      f"({proto_stats['percentage']:.1f}%)")
        
        print("\n3. Top bandwidth consumers:")
        
        # Find top bandwidth consuming hosts
        top_consumers = analyzer.get_top_bandwidth_consumers(packets, top_n=10)
        for i, (ip, bytes_used) in enumerate(top_consumers[:5]):
            print(f"   {i+1}. {ip}: {format_bytes(bytes_used)}")
        
        print("\n4. Bandwidth trends:")
        
        # Analyze bandwidth trends over time
        trends = analyzer.analyze_bandwidth_trends(packets)
        print(f"   Peak usage time: {trends['peak_time']}")
        print(f"   Peak rate: {format_bytes(trends['peak_rate'])}/s")
        print(f"   Average rate: {format_bytes(trends['avg_rate'])}/s")
        
        print("\n5. Application bandwidth usage:")
        
        # Analyze bandwidth by application (based on ports)
        app_bandwidth = analyzer.analyze_application_bandwidth(packets)
        for app, usage in app_bandwidth.items():
            print(f"   {app}: {format_bytes(usage['bytes'])} "
                  f"({usage['percentage']:.1f}%)")
        
        # Create bandwidth visualization
        plot_protocol_distribution(
            packets,
            chart_type='bar',
            save_path='bandwidth_by_protocol.png'
        )
        print("\n   ✅ Bandwidth distribution chart saved")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")

def real_time_monitoring():
    """Demonstrate real-time network monitoring."""
    try:
        from pktanalyzer import (
            AsyncPacketCapture,
            PacketAnalyzer,
            setup_logging
        )
        import threading
        import queue
        
        print("\n" + "="*50)
        print("⏱️  Real-time Network Monitoring")
        print("=" * 50)
        
        # Setup real-time monitoring
        logger = setup_logging(level='INFO')
        packet_queue = queue.Queue()
        analyzer = PacketAnalyzer()
        
        print("Starting real-time packet capture...")
        print("(This will run for 60 seconds)")
        
        # Callback function for real-time analysis
        def packet_callback(packet):
            """Process packets in real-time."""
            packet_queue.put(packet)
        
        # Start async capture
        async_capture = AsyncPacketCapture(
            interface=None,
            filter_str="ip",
            callback=packet_callback
        )
        
        # Start monitoring
        async_capture.start()
        
        # Monitor for 60 seconds
        start_time = time.time()
        packet_count = 0
        bandwidth_samples = []
        
        print("\n📊 Real-time statistics (updating every 10 seconds):")
        
        while time.time() - start_time < 60:  # Monitor for 1 minute
            time.sleep(10)  # Update every 10 seconds
            
            # Get packets from queue
            current_packets = []
            while not packet_queue.empty():
                try:
                    current_packets.append(packet_queue.get_nowait())
                except queue.Empty:
                    break
            
            if current_packets:
                packet_count += len(current_packets)
                
                # Calculate current bandwidth
                current_bandwidth = analyzer.calculate_current_bandwidth(current_packets)
                bandwidth_samples.append(current_bandwidth)
                
                elapsed = time.time() - start_time
                print(f"   Time: {elapsed:.0f}s | "
                      f"Packets: {packet_count} | "
                      f"Rate: {len(current_packets)/10:.1f} pps | "
                      f"Bandwidth: {current_bandwidth:.2f} Mbps")
        
        # Stop capture
        async_capture.stop()
        
        print(f"\n✅ Real-time monitoring completed")
        print(f"   Total packets captured: {packet_count}")
        print(f"   Average bandwidth: {sum(bandwidth_samples)/len(bandwidth_samples):.2f} Mbps")
        print(f"   Peak bandwidth: {max(bandwidth_samples):.2f} Mbps")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")

def network_health_assessment():
    """Demonstrate network health assessment."""
    try:
        from pktanalyzer import (
            capture_packets,
            PacketAnalyzer,
            analyze_packets,
            create_report
        )
        
        print("\n" + "="*50)
        print("🏥 Network Health Assessment")
        print("=" * 50)
        
        print("Conducting comprehensive network health check...")
        
        # Capture packets for health assessment
        packets = capture_packets(
            count=400,
            timeout=150,
            filter_str="ip"
        )
        
        if not packets:
            print("❌ No packets captured")
            return
        
        print(f"✅ Captured {len(packets)} packets")
        
        analyzer = PacketAnalyzer()
        
        print("\n🔍 Health Assessment Results:")
        
        # Overall network analysis
        overall_stats = analyze_packets(packets)
        
        # Calculate health metrics
        health_metrics = analyzer.calculate_health_metrics(packets)
        
        print(f"\n1. Connectivity Health:")
        print(f"   Connection success rate: {health_metrics['connection_success_rate']:.1f}%")
        print(f"   Average response time: {health_metrics['avg_response_time']:.2f} ms")
        print(f"   Timeout rate: {health_metrics['timeout_rate']:.2f}%")
        
        print(f"\n2. Performance Health:")
        print(f"   Throughput efficiency: {health_metrics['throughput_efficiency']:.1f}%")
        print(f"   Bandwidth utilization: {health_metrics['bandwidth_utilization']:.1f}%")
        print(f"   Protocol distribution health: {health_metrics['protocol_health']}")
        
        print(f"\n3. Security Health:")
        print(f"   Suspicious activity score: {health_metrics['security_score']:.1f}/10")
        print(f"   Anomaly detection rate: {health_metrics['anomaly_rate']:.2f}%")
        print(f"   Encryption usage: {health_metrics['encryption_percentage']:.1f}%")
        
        # Calculate overall health score
        overall_health = analyzer.calculate_overall_health_score(health_metrics)
        health_status = "Excellent" if overall_health > 90 else \
                       "Good" if overall_health > 75 else \
                       "Fair" if overall_health > 60 else "Poor"
        
        print(f"\n📊 Overall Network Health Score: {overall_health:.1f}/100 ({health_status})")
        
        # Generate health recommendations
        recommendations = analyzer.generate_health_recommendations(health_metrics)
        if recommendations:
            print(f"\n💡 Recommendations:")
            for i, rec in enumerate(recommendations[:5]):
                print(f"   {i+1}. {rec}")
        
        # Create health report
        health_report = {
            'assessment_date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'overall_score': overall_health,
            'status': health_status,
            'metrics': health_metrics,
            'recommendations': recommendations,
            'packet_summary': overall_stats
        }
        
        report_path = create_report(
            packets,
            health_report,
            'network_health_report.html',
            report_type='health'
        )
        print(f"\n✅ Health assessment report saved: {report_path}")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")

def main():
    """Run performance monitoring examples."""
    print("📊 PktAnalyzer Performance Monitoring Examples")
    print("=" * 60)
    print("This script demonstrates network performance and health monitoring")
    print()
    
    try:
        network_performance_monitoring()
        bandwidth_monitoring()
        real_time_monitoring()
        network_health_assessment()
        
        print("\n" + "="*60)
        print("✅ Performance monitoring examples completed!")
        print("\nGenerated files:")
        print("- performance_monitor.log")
        print("- performance_timeline.png")
        print("- bandwidth_by_protocol.png")
        print("- network_health_report.html")
        print("\nPerformance insights:")
        print("1. Monitor bandwidth usage trends")
        print("2. Track network health metrics regularly")
        print("3. Set up alerts for performance degradation")
        print("4. Analyze peak usage patterns")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Performance monitoring interrupted by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")

if __name__ == "__main__":
    main()