# PktAnalyzer

🔍 **A comprehensive Python library for network packet capture, analysis, and visualization**

PktAnalyzer is a powerful and educational packet analysis library built on top of Scapy, designed for network security education, performance monitoring, and traffic analysis.

## ✨ Features

### 📡 Packet Capture
- **Live packet capture** from network interfaces
- **PCAP/PCAPNG file** loading and saving
- **BPF filtering** support for precise capture
- **Multiple interface** support

### 🔬 Analysis
- **Protocol statistics** and distribution analysis
- **Traffic pattern** recognition
- **Bandwidth and throughput** calculation
- **Top talkers** analysis

### 🔒 Security Features
- **Attack detection** (SYN flood, ICMP flood, port scans)
- **Anomaly detection** and behavioral analysis
- **Security monitoring** capabilities

### 🎨 Visualization
- **Protocol distribution** charts
- **Traffic timeline** analysis
- **Network topology** visualization
- **Interactive plots** with matplotlib

### 🛠️ Utilities
- **Flexible filtering** system
- **Data export** (JSON, CSV)
- **Logging and configuration** management

## 🚀 Quick Start

### Installation

```bash
# Install dependencies
pip install scapy matplotlib numpy

# Install PktAnalyzer
pip install -e .
```

### Basic Usage

```python
from pktanalyzer import capture_packets, analyze_packets, plot_protocol_distribution

# Capture packets
packets = capture_packets(count=100, filter_str="tcp")

# Analyze
stats = analyze_packets(packets)
print(f"Total packets: {stats['total_packets']}")

# Visualize
plot_protocol_distribution(packets, save_path="protocols.png")
```

## 📁 Project Structure

```
pktanalyzer/
├── __init__.py          # Main package exports
├── capture.py           # Packet capture functionality
├── analysis.py          # Statistical analysis
├── filters.py           # IP, protocol, port filtering
├── visualization.py     # Charts and plots
├── utils.py            # Helper functions, export utilities
examples/
├── basic_sniff.py      # Basic packet sniffing
├── analyze_pcap.py     # PCAP file analysis
├── live_monitor.py     # Real-time monitoring
README.md               # This file
setup.py               # Installation configuration
```

## 📖 Examples

### Basic Packet Sniffing
```python
# examples/basic_sniff.py
from pktanalyzer import capture_packets, setup_logging

logger = setup_logging()
packets = capture_packets(count=50, interface="eth0")
print(f"Captured {len(packets)} packets")
```

### PCAP Analysis
```python
# examples/analyze_pcap.py
from pktanalyzer import load_pcap, analyze_packets, export_stats

packets = load_pcap("traffic.pcap")
stats = analyze_packets(packets)
export_stats(stats, "analysis_report.json")
```

### Live Monitoring
```python
# examples/live_monitor.py
from pktanalyzer import PacketCapture, PacketAnalyzer

capture = PacketCapture(interface="eth0")
analyzer = PacketAnalyzer()

# Real-time packet processing
def process_packet(packet):
    # Analyze each packet as it arrives
    pass

capture.start_capture(callback=process_packet)
```

## 🔧 Requirements

- Python 3.7+
- Scapy >= 2.4.5
- Matplotlib >= 3.3.0
- Numpy >= 1.19.0

## ⚠️ Notes

- **Admin privileges** required for live packet capture
- **Windows users**: Install Npcap from https://nmap.org/npcap/
- **Linux users**: May need to run with sudo for raw socket access

## 📝 License

MIT License - See LICENSE file for details

## 🤝 Contributing

1. Fork the repository
2. Create feature branch
3. Make changes
4. Add tests
5. Submit pull request

## 📚 Documentation

For detailed documentation and advanced usage examples, see the `examples/` directory.

## 🆘 Support

- Check examples for common use cases
- Review documentation
- Report issues on GitHub

---
**PktAnalyzer** - Making network analysis accessible and educational! 🚀