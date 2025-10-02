# PktAnalyzer Examples

This directory contains practical examples demonstrating the core features of PktAnalyzer.

## Quick Start

Make sure dependencies are installed first:
```bash
pip install scapy matplotlib numpy
```

Then run any example:
```bash
python basic_sniff.py
python analyze_pcap.py
python live_monitor.py
```

## Examples Overview

### 1. basic_sniff.py
**Basic packet capture and analysis**

- Live packet capture from network interface
- Basic protocol statistics
- Simple packet filtering
- Admin privilege checking

**What you'll learn:**
- How to capture packets with `capture_packets()`
- Basic packet analysis and statistics
- Protocol distribution analysis
- Handling capture errors and permissions

**Sample output:**
```
🔍 Basic Packet Sniffing Example
✅ Successfully captured 20 packets
📊 Basic statistics:
   Total size: 15420 bytes
   Average packet size: 771.0 bytes
🌐 Protocol distribution:
   TCP: 18 packets (90.0%)
   UDP: 2 packets (10.0%)
```

### 2. analyze_pcap.py
**PCAP file analysis and export**

- Load and analyze existing PCAP files
- Advanced filtering by protocol and IP
- Data export to JSON/CSV formats
- Visualization generation

**What you'll learn:**
- Loading PCAP files with `load_pcap()`
- Using filters: `filter_by_protocol()`, `filter_by_ip()`
- Exporting analysis results
- Creating protocol distribution charts

**Features demonstrated:**
- File-based packet analysis
- Top talkers identification
- Multiple export formats
- Automated visualization

### 3. live_monitor.py
**Real-time network monitoring**

- Interactive real-time packet monitoring
- Live statistics updates
- Custom BPF filter configuration
- Packet capture to file

**What you'll learn:**
- Real-time packet processing
- Live statistics calculation
- Interactive filter selection
- Continuous monitoring techniques

**Interactive features:**
- Multiple filter presets
- Live statistics display
- Graceful shutdown with Ctrl+C
- Optional packet saving

## Prerequisites

### System Requirements
- Python 3.7+
- Network interface access
- **Admin/Root privileges** for packet capture

### Windows Users
1. Install Npcap: https://nmap.org/npcap/
2. Run PowerShell/CMD as Administrator
3. Install Python dependencies

### Linux/Mac Users
1. Install libpcap development headers
2. Run with sudo for raw socket access
3. Install Python dependencies

## Common Issues & Solutions

### "No module named 'scapy'"
```bash
pip install scapy matplotlib numpy
```

### "Permission denied" or "Operation not permitted"
- **Windows**: Run as Administrator
- **Linux/Mac**: Run with `sudo python script.py`

### "No packets captured"
- Check network connectivity
- Verify interface is active
- Try different filter expressions
- Check firewall settings

### "Interface not found"
- Use `None` for default interface
- List available interfaces in code
- Check network adapter status

## Example Commands

```bash
# Run basic sniffing (requires admin)
python basic_sniff.py

# Analyze existing PCAP file
python analyze_pcap.py

# Start live monitoring
python live_monitor.py

# Install with full features
pip install -e .[full]
```

## Understanding the Output

### Packet Capture
- **Total packets**: Number of packets captured
- **Total size**: Combined size of all packets
- **Average size**: Mean packet size in bytes

### Protocol Distribution
- **TCP**: Transmission Control Protocol packets
- **UDP**: User Datagram Protocol packets  
- **ICMP**: Internet Control Message Protocol
- **Other**: ARP, unknown protocols, etc.

### Top Talkers
- Source IP addresses generating most traffic
- Useful for identifying active hosts
- Helps in network troubleshooting

## Next Steps

1. **Try your own PCAP files** with `analyze_pcap.py`
2. **Experiment with filters** in `live_monitor.py`  
3. **Combine examples** to create custom analysis tools
4. **Explore the main library** documentation
5. **Build your own monitoring scripts**

## Advanced Usage

Check the main `examples/` directory for more sophisticated examples:
- `advanced_analysis.py` - Complex filtering and analysis
- `security_analysis.py` - Security-focused monitoring
- `performance_monitoring.py` - Network performance metrics

---
**Happy packet analyzing!** 🔍📊
**Security monitoring and threat detection**

- Network security monitoring
- Attack detection (SYN flood, port scans)
- Incident response workflow
- Threat hunting capabilities
- Security reporting

**Features demonstrated:**
- `SecurityAnalyzer` for threat detection
- `detect_syn_flood()`, `detect_port_scan()`
- `detect_suspicious_activity()` for anomalies
- Incident response procedures
- Security report generation

### 4. performance_monitoring.py
**Network performance and health monitoring**

- Bandwidth analysis
- Latency measurement
- QoS assessment
- Real-time monitoring
- Network health scoring

**Features demonstrated:**
- `calculate_bandwidth()` for throughput analysis
- `analyze_latency()` for performance metrics
- `AsyncPacketCapture` for real-time monitoring
- Network health assessment
- Performance visualization

## Prerequisites

### Required Dependencies

```bash
pip install scapy matplotlib numpy
```

### Optional Dependencies

```bash
pip install geoip2  # For IP geolocation features
pip install plotly  # For interactive visualizations
```

### System Requirements

- **Administrator/Root privileges** required for live packet capture
- **Network interface** for packet capture
- **Python 3.7+** for library compatibility

## Usage Patterns

### Basic Analysis Workflow

```python
from pktanalyzer import capture_packets, analyze_packets, plot_protocol_distribution

# 1. Capture packets
packets = capture_packets(count=100, filter_str="ip")

# 2. Analyze traffic
stats = analyze_packets(packets)

# 3. Visualize results
plot_protocol_distribution(packets, save_path="analysis.png")
```

### Security Monitoring Workflow

```python
from pktanalyzer import capture_packets, SecurityAnalyzer

# 1. Capture traffic
packets = capture_packets(count=500, filter_str="tcp or udp")

# 2. Initialize security analyzer
security = SecurityAnalyzer()

# 3. Detect threats
syn_flood = security.detect_syn_flood(packets)
port_scan = security.detect_port_scan(packets)

# 4. Generate security report
if syn_flood['detected'] or port_scan['detected']:
    print("🚨 Security threats detected!")
```

### Performance Monitoring Workflow

```python
from pktanalyzer import capture_packets, PacketAnalyzer

# 1. Capture performance data
packets = capture_packets(count=1000, timeout=120)

# 2. Analyze performance
analyzer = PacketAnalyzer()
bandwidth = analyzer.calculate_bandwidth(packets)
latency = analyzer.analyze_latency(packets)

# 3. Assess network health
health_score = analyzer.calculate_overall_health_score({
    'bandwidth': bandwidth,
    'latency': latency
})
```

## File Formats

### Input Formats
- **Live capture**: Direct from network interfaces
- **PCAP files**: Standard packet capture format
- **PCAPNG files**: Next-generation packet capture format

### Output Formats
- **PNG**: Charts and visualizations
- **HTML**: Comprehensive reports
- **JSON**: Data export and analysis results
- **CSV**: Tabular data export
- **TXT**: Log files and summaries

## Common Use Cases

### 1. Network Troubleshooting
```python
# Capture and analyze network issues
packets = capture_packets(count=200, filter_str="tcp")
analysis = analyze_packets(packets)

# Check for connection problems
failed_connections = filter_by_flags(packets, ['RST', 'FIN'])
print(f"Failed connections: {len(failed_connections)}")
```

### 2. Security Incident Response
```python
# Load suspicious traffic from file
packets = load_pcap("suspicious_traffic.pcap")

# Perform security analysis
security = SecurityAnalyzer()
threats = security.detect_all_threats(packets)

# Generate incident report
create_incident_report(packets, threats, "incident_report.html")
```

### 3. Bandwidth Monitoring
```python
# Monitor bandwidth usage
packets = capture_packets(count=1000, timeout=300)

# Analyze bandwidth by protocol
tcp_packets = filter_by_protocol(packets, 'TCP')
udp_packets = filter_by_protocol(packets, 'UDP')

tcp_bandwidth = calculate_protocol_bandwidth(tcp_packets)
udp_bandwidth = calculate_protocol_bandwidth(udp_packets)
```

### 4. Educational Network Analysis
```python
# Demonstrate protocol behaviors
packets = capture_packets(count=50, filter_str="icmp or dns")

# Show protocol distribution
plot_protocol_distribution(packets)

# Explain packet contents
for packet in packets[:5]:
    summary = summarize_packet(packet)
    print(f"Packet: {summary}")
```

## Tips and Best Practices

### Performance Tips
1. **Use appropriate filter strings** to capture only relevant traffic
2. **Limit packet count** for faster processing
3. **Use async capture** for real-time monitoring
4. **Process packets in batches** for large datasets

### Security Tips
1. **Run with minimal privileges** when possible
2. **Validate input files** before processing
3. **Use secure storage** for captured data
4. **Implement proper logging** for audit trails

### Troubleshooting
1. **Check admin privileges** for packet capture issues
2. **Verify network interfaces** are available
3. **Install dependencies** if import errors occur
4. **Check firewall settings** that might block capture

## Learning Path

1. **Start with basic_usage.py** to understand core concepts
2. **Explore advanced_analysis.py** for filtering and analysis
3. **Study security_analysis.py** for threat detection
4. **Master performance_monitoring.py** for network optimization

## Contributing

To add new examples:

1. Follow the existing code structure
2. Include comprehensive error handling
3. Add detailed comments and documentation
4. Test with various network conditions
5. Update this README with new features

## Support

For questions or issues:
- Check the main PktAnalyzer documentation
- Review error messages carefully
- Verify system prerequisites
- Test with minimal examples first

Happy packet analysis! 🔍📊🔒