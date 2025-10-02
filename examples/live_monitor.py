#!/usr/bin/env python3
"""
Live Network Monitoring Example

This example demonstrates real-time network monitoring using PktAnalyzer.
"""

import sys
import os
import time
import threading
from collections import defaultdict, Counter

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class LiveMonitor:
    """Real-time network traffic monitor."""
    
    def __init__(self):
        self.packets = []
        self.stats = defaultdict(int)
        self.protocols = Counter()
        self.ips = Counter()
        self.running = False
        self.start_time = time.time()
    
    def packet_callback(self, packet):
        """Process each captured packet."""
        self.packets.append(packet)
        self.stats['total_packets'] += 1
        self.stats['total_bytes'] += len(packet)
        
        # Track protocols
        if packet.haslayer('TCP'):
            self.protocols['TCP'] += 1
        elif packet.haslayer('UDP'):
            self.protocols['UDP'] += 1
        elif packet.haslayer('ICMP'):
            self.protocols['ICMP'] += 1
        else:
            self.protocols['Other'] += 1
        
        # Track IPs
        if packet.haslayer('IP'):
            self.ips[packet['IP'].src] += 1
            self.ips[packet['IP'].dst] += 1
    
    def print_stats(self):
        """Print current statistics."""
        elapsed = time.time() - self.start_time
        
        print(f"\n📊 Live Statistics (Running for {elapsed:.0f}s)")
        print("=" * 50)
        
        # Basic stats
        total = self.stats['total_packets']
        bytes_total = self.stats['total_bytes']
        pps = total / elapsed if elapsed > 0 else 0
        bps = bytes_total / elapsed if elapsed > 0 else 0
        
        print(f"Total Packets: {total}")
        print(f"Total Bytes: {bytes_total:,}")
        print(f"Packets/sec: {pps:.1f}")
        print(f"Bytes/sec: {bps:,.0f}")
        
        # Protocol distribution
        print(f"\nProtocol Distribution:")
        for proto, count in self.protocols.most_common():
            percentage = (count / total) * 100 if total > 0 else 0
            print(f"  {proto}: {count} ({percentage:.1f}%)")
        
        # Top talkers
        print(f"\nTop Source IPs:")
        for ip, count in self.ips.most_common(5):
            print(f"  {ip}: {count} packets")
        
        print("-" * 50)
    
    def start_monitoring(self, interface=None, filter_str="ip"):
        """Start live monitoring."""
        try:
            from pktanalyzer import PacketCapture
            
            print(f"🔴 Starting live monitoring...")
            print(f"Interface: {interface or 'default'}")
            print(f"Filter: {filter_str}")
            print("Press Ctrl+C to stop\n")
            
            # Create capture instance
            capture = PacketCapture(interface=interface, verbose=False)
            
            self.running = True
            
            # Start stats display thread
            def stats_updater():
                while self.running:
                    time.sleep(5)  # Update every 5 seconds
                    if self.stats['total_packets'] > 0:
                        self.print_stats()
            
            stats_thread = threading.Thread(target=stats_updater, daemon=True)
            stats_thread.start()
            
            # Start packet capture (blocking)
            capture.capture_packets(
                count=0,  # Unlimited
                filter_expr=filter_str,
                callback=self.packet_callback
            )
            
        except KeyboardInterrupt:
            print("\n⏹️  Monitoring stopped by user")
            self.running = False
        except Exception as e:
            print(f"❌ Error during monitoring: {e}")
            self.running = False

def main():
    """Live monitoring example."""
    try:
        from pktanalyzer import setup_logging
        
        print("📡 Live Network Monitoring Example")
        print("=" * 40)
        
        # Setup logging (less verbose for live monitoring)
        logger = setup_logging(verbose=False)
        
        # Check admin privileges
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                print("⚠️  Warning: Not running as administrator")
                print("   Live capture may not work properly")
                print("   Try running as administrator for best results\n")
        except:
            print("ℹ️  Running on non-Windows system\n")
        
        # Create monitor instance
        monitor = LiveMonitor()
        
        # Configuration
        print("Configuration options:")
        print("1. Monitor all IP traffic (default)")
        print("2. Monitor TCP traffic only")  
        print("3. Monitor HTTP traffic only")
        print("4. Custom filter")
        
        choice = input("\nSelect option (1-4) or press Enter for default: ").strip()
        
        filter_options = {
            '1': 'ip',
            '2': 'tcp', 
            '3': 'tcp port 80 or tcp port 443',
            '4': None  # Custom
        }
        
        if choice == '4':
            filter_str = input("Enter custom BPF filter: ").strip()
            if not filter_str:
                filter_str = 'ip'
        else:
            filter_str = filter_options.get(choice, 'ip')
        
        print(f"\nSelected filter: {filter_str}")
        
        # Start monitoring
        monitor.start_monitoring(filter_str=filter_str)
        
        # Final statistics
        print(f"\n📈 Final Statistics:")
        monitor.print_stats()
        
        # Save captured data
        if monitor.packets:
            save_choice = input("\nSave captured packets to PCAP file? (y/N): ").strip().lower()
            if save_choice == 'y':
                from pktanalyzer import save_pcap
                filename = f"live_capture_{int(time.time())}.pcap"
                save_pcap(monitor.packets, filename)
                print(f"✅ Packets saved to: {filename}")
        
        print("✅ Live monitoring completed!")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("   Make sure to install dependencies:")
        print("   pip install scapy matplotlib numpy")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()