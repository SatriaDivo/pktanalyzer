"""
Security Analysis Example

This example demonstrates the security analysis capabilities of PktAnalyzer,
including attack detection, threat analysis, and security monitoring.
"""

import sys
import os

# Add parent directory to path to import pktanalyzer
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def network_security_monitoring():
    """Demonstrate network security monitoring capabilities."""
    try:
        from pktanalyzer import (
            capture_packets,
            SecurityAnalyzer,
            filter_by_protocol,
            create_report,
            setup_logging
        )
        
        print("🔒 Network Security Monitoring Example")
        print("=" * 50)
        
        # Setup logging for security events
        logger = setup_logging(level='INFO', log_file='security_monitor.log')
        
        print("1. Capturing network traffic for security analysis...")
        
        # Capture packets with focus on security-relevant traffic
        packets = capture_packets(
            count=300,
            timeout=120,
            filter_str="tcp or udp or icmp"  # All major protocols
        )
        
        if not packets:
            print("❌ No packets captured")
            return
        
        print(f"✅ Captured {len(packets)} packets")
        
        # Initialize security analyzer
        security = SecurityAnalyzer()
        
        print("\n2. Scanning for security threats:")
        
        # Detect SYN flood attacks
        syn_flood = security.detect_syn_flood(packets, threshold=20)
        if syn_flood['detected']:
            print("🚨 SYN FLOOD DETECTED!")
            print(f"   Attack rate: {syn_flood['rate']:.2f} SYN packets/sec")
            print(f"   Target: {syn_flood['target']}")
            print(f"   Sources: {len(syn_flood['sources'])} unique IPs")
        else:
            print("✅ No SYN flood detected")
        
        # Detect ICMP flood attacks
        icmp_flood = security.detect_icmp_flood(packets, threshold=50)
        if icmp_flood['detected']:
            print("🚨 ICMP FLOOD DETECTED!")
            print(f"   Rate: {icmp_flood['rate']:.2f} ICMP packets/sec")
            print(f"   Target: {icmp_flood['target']}")
        else:
            print("✅ No ICMP flood detected")
        
        # Detect port scanning
        port_scan = security.detect_port_scan(packets, threshold=10)
        if port_scan['detected']:
            print("🚨 PORT SCAN DETECTED!")
            print(f"   Scanner: {port_scan['scanner_ip']}")
            print(f"   Target: {port_scan['target_ip']}")
            print(f"   Ports scanned: {len(port_scan['ports'])}")
            print(f"   Scan rate: {port_scan['scan_rate']:.2f} ports/sec")
        else:
            print("✅ No port scan detected")
        
        print("\n3. Advanced threat detection:")
        
        # Detect suspicious activities
        suspicious = security.detect_suspicious_activity(packets)
        if suspicious:
            print(f"⚠️  {len(suspicious)} suspicious activities detected:")
            for i, activity in enumerate(suspicious[:5]):  # Show first 5
                print(f"   {i+1}. {activity}")
        else:
            print("✅ No suspicious activity detected")
        
        # Analyze traffic for anomalies
        anomalies = security.detect_anomalies(packets)
        if anomalies:
            print(f"⚠️  {len(anomalies)} traffic anomalies detected:")
            for anomaly in anomalies[:3]:  # Show first 3
                print(f"   - {anomaly}")
        else:
            print("✅ No traffic anomalies detected")
        
        print("\n4. Protocol-specific security analysis:")
        
        # TCP security analysis
        tcp_packets = filter_by_protocol(packets, 'TCP')
        if tcp_packets:
            tcp_analysis = security.analyze_tcp_security(tcp_packets)
            print(f"   TCP connections: {tcp_analysis['total_connections']}")
            print(f"   Failed connections: {tcp_analysis['failed_connections']}")
            print(f"   Suspicious flags: {tcp_analysis['suspicious_flags']}")
        
        # DNS security analysis
        dns_packets = filter_by_protocol(packets, 'DNS')
        if dns_packets:
            dns_analysis = security.analyze_dns_security(dns_packets)
            print(f"   DNS queries: {dns_analysis['total_queries']}")
            print(f"   Suspicious domains: {len(dns_analysis['suspicious_domains'])}")
        
        print("\n5. Generating security report:")
        
        # Create comprehensive security report
        report_data = {
            'total_packets': len(packets),
            'security_events': {
                'syn_flood': syn_flood,
                'icmp_flood': icmp_flood,
                'port_scan': port_scan,
                'suspicious_activities': suspicious,
                'anomalies': anomalies
            },
            'recommendations': security.get_security_recommendations(packets)
        }
        
        report_path = create_report(
            packets, 
            report_data,
            'security_analysis_report.html',
            report_type='security'
        )
        print(f"   ✅ Security report saved: {report_path}")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")

def incident_response_workflow():
    """Demonstrate incident response workflow using PktAnalyzer."""
    try:
        from pktanalyzer import (
            load_pcap,
            SecurityAnalyzer,
            PacketFilter,
            create_analysis_dashboard,
            export_stats
        )
        
        print("\n" + "="*50)
        print("🚨 Incident Response Workflow")
        print("=" * 50)
        
        # This example assumes you have a suspicious PCAP file
        pcap_file = "suspicious_traffic.pcap"
        
        if not os.path.exists(pcap_file):
            print(f"ℹ️  Sample PCAP file '{pcap_file}' not found.")
            print("   For incident response workflow:")
            print("   1. Place a suspicious .pcap file in this directory")
            print("   2. Rename it to 'suspicious_traffic.pcap'")
            print("   3. Run this example again")
            
            # Create a simulated incident for demonstration
            print("\n   Simulating incident response with live capture...")
            return simulate_incident_response()
        
        print(f"📁 Loading suspicious traffic from {pcap_file}...")
        packets = load_pcap(pcap_file)
        
        if not packets:
            print("❌ No packets loaded")
            return
        
        print(f"✅ Loaded {len(packets)} packets for analysis")
        
        # Step 1: Initial triage
        print("\n🔍 Step 1: Initial Triage")
        security = SecurityAnalyzer()
        
        # Quick security assessment
        initial_assessment = security.quick_security_assessment(packets)
        print(f"   Risk level: {initial_assessment['risk_level']}")
        print(f"   Threat indicators: {len(initial_assessment['indicators'])}")
        
        # Step 2: Deep analysis
        print("\n🔬 Step 2: Deep Analysis")
        
        # Identify attack vectors
        attack_vectors = security.identify_attack_vectors(packets)
        for vector in attack_vectors:
            print(f"   - {vector}")
        
        # Step 3: Evidence collection
        print("\n📋 Step 3: Evidence Collection")
        
        pf = PacketFilter()
        
        # Extract malicious traffic
        malicious_traffic = pf.filter_malicious_traffic(packets)
        print(f"   Malicious packets: {len(malicious_traffic)}")
        
        # Extract communication endpoints
        endpoints = security.extract_communication_endpoints(packets)
        print(f"   Unique endpoints: {len(endpoints)}")
        
        # Step 4: Timeline reconstruction
        print("\n📅 Step 4: Timeline Reconstruction")
        
        timeline = security.reconstruct_attack_timeline(packets)
        print(f"   Attack duration: {timeline['duration']}")
        print(f"   Key events: {len(timeline['events'])}")
        
        # Step 5: Reporting
        print("\n📊 Step 5: Incident Reporting")
        
        # Generate incident report
        incident_report = {
            'incident_id': 'INC-2024-001',
            'severity': initial_assessment['risk_level'],
            'attack_vectors': attack_vectors,
            'timeline': timeline,
            'evidence': {
                'total_packets': len(packets),
                'malicious_packets': len(malicious_traffic),
                'endpoints': len(endpoints)
            }
        }
        
        # Export evidence
        evidence_file = export_stats(
            packets, 
            incident_report,
            'incident_evidence.json'
        )
        print(f"   ✅ Evidence exported: {evidence_file}")
        
        # Create visual analysis
        dashboard_path = create_analysis_dashboard(
            packets,
            'incident_analysis_dashboard.png',
            include_security=True
        )
        print(f"   ✅ Visual analysis: {dashboard_path}")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")

def simulate_incident_response():
    """Simulate incident response with live capture."""
    try:
        from pktanalyzer import (
            capture_packets,
            SecurityAnalyzer,
            PacketFilter
        )
        
        print("🎭 Simulating incident response scenario...")
        
        # Capture packets that might contain security events
        packets = capture_packets(
            count=200,
            timeout=60,
            filter_str="tcp or icmp"
        )
        
        if not packets:
            print("❌ No packets captured for simulation")
            return
        
        print(f"✅ Captured {len(packets)} packets for simulation")
        
        security = SecurityAnalyzer()
        
        # Simulate threat detection
        print("\n🔍 Threat Detection Results:")
        
        # Check for various threats (simulated)
        threats = [
            "Unusual connection patterns detected",
            "High volume of ICMP traffic",
            "Multiple failed connection attempts",
            "Suspicious user agent strings",
            "Potential data exfiltration"
        ]
        
        detected_threats = threats[:2]  # Simulate detecting first 2
        
        for threat in detected_threats:
            print(f"   ⚠️  {threat}")
        
        print(f"\n✅ Incident response simulation completed")
        print(f"   Threats detected: {len(detected_threats)}")
        print(f"   Packets analyzed: {len(packets)}")
        
    except Exception as e:
        print(f"❌ Simulation error: {e}")

def threat_hunting_example():
    """Demonstrate threat hunting capabilities."""
    try:
        from pktanalyzer import (
            capture_packets,
            SecurityAnalyzer,
            PacketFilter,
            filter_by_ip,
            get_top_talkers
        )
        
        print("\n" + "="*50)
        print("🎯 Threat Hunting Example")
        print("=" * 50)
        
        print("Collecting network data for threat hunting...")
        
        # Capture comprehensive network data
        packets = capture_packets(
            count=250,
            timeout=90,
            filter_str="ip"
        )
        
        if not packets:
            print("❌ No packets captured")
            return
        
        print(f"✅ Captured {len(packets)} packets")
        
        security = SecurityAnalyzer()
        pf = PacketFilter()
        
        print("\n1. Baseline establishment:")
        
        # Establish network baseline
        baseline = security.establish_network_baseline(packets)
        print(f"   Normal protocols: {', '.join(baseline['normal_protocols'])}")
        print(f"   Typical packet size: {baseline['typical_size']} bytes")
        print(f"   Expected traffic rate: {baseline['traffic_rate']:.2f} pps")
        
        print("\n2. Anomaly hunting:")
        
        # Hunt for unusual patterns
        unusual_patterns = security.hunt_unusual_patterns(packets)
        if unusual_patterns:
            print(f"   Found {len(unusual_patterns)} unusual patterns:")
            for pattern in unusual_patterns[:3]:
                print(f"     - {pattern}")
        else:
            print("   No unusual patterns detected")
        
        print("\n3. IOC (Indicators of Compromise) search:")
        
        # Search for known IOCs
        iocs = security.search_iocs(packets)
        if iocs:
            print(f"   Found {len(iocs)} potential IOCs:")
            for ioc in iocs[:3]:
                print(f"     - {ioc}")
        else:
            print("   No known IOCs detected")
        
        print("\n4. Behavioral analysis:")
        
        # Analyze host behaviors
        behaviors = security.analyze_host_behaviors(packets)
        print(f"   Analyzed {len(behaviors)} unique hosts")
        
        suspicious_hosts = [host for host, behavior in behaviors.items() 
                          if behavior.get('risk_score', 0) > 7]
        
        if suspicious_hosts:
            print(f"   Suspicious hosts: {len(suspicious_hosts)}")
            for host in suspicious_hosts[:3]:
                print(f"     - {host}")
        else:
            print("   No suspicious host behavior detected")
        
        print("\n5. Communication analysis:")
        
        # Analyze communication patterns
        comm_analysis = security.analyze_communications(packets)
        print(f"   Total conversations: {comm_analysis['total_conversations']}")
        print(f"   Encrypted traffic: {comm_analysis['encrypted_percentage']:.1f}%")
        print(f"   External communications: {comm_analysis['external_comms']}")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
    except Exception as e:
        print(f"❌ Error: {e}")

def main():
    """Run security analysis examples."""
    print("🔒 PktAnalyzer Security Analysis Examples")
    print("=" * 60)
    print("This script demonstrates security and threat detection capabilities")
    print()
    
    try:
        network_security_monitoring()
        incident_response_workflow()
        threat_hunting_example()
        
        print("\n" + "="*60)
        print("✅ Security analysis examples completed!")
        print("\nGenerated files:")
        print("- security_monitor.log")
        print("- security_analysis_report.html")
        print("- incident_evidence.json")
        print("- incident_analysis_dashboard.png")
        print("\nSecurity insights:")
        print("1. Monitor logs for security events")
        print("2. Review security reports regularly")
        print("3. Investigate any detected anomalies")
        print("4. Update threat indicators periodically")
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Security analysis interrupted by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")

if __name__ == "__main__":
    main()