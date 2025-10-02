#!/usr/bin/env python3
"""
Basic Packet Sniffing Example

This example demonstrates basic packet capture functionality using PktAnalyzer.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def main():
    """Basic packet sniffing example."""
    try:
        from pktanalyzer import capture_packets, setup_logging
        
        print("🔍 Basic Packet Sniffing Example")
        print("=" * 40)
        
        # Setup logging
        logger = setup_logging(verbose=True)
        
        # Check admin privileges
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                print("⚠️  Warning: Not running as administrator")
                print("   Packet capture may not work properly")
        except:
            print("ℹ️  Running on non-Windows system")
        
        print("\n1. Starting packet capture...")
        print("   Capturing 20 packets (or timeout in 30 seconds)")
        print("   Filter: TCP packets only")
        
        # Capture packets
        packets = capture_packets(
            count=20,
            timeout=30,
            filter_str="tcp",
            interface=None  # Use default interface
        )
        
        if not packets:
            print("❌ No packets captured")
            print("   - Check your internet connection")
            print("   - Try running as administrator")
            print("   - Check network interface")
            return
        
        print(f"✅ Successfully captured {len(packets)} packets")
        
        print("\n2. Packet summary:")
        for i, packet in enumerate(packets[:5]):  # Show first 5
            print(f"   {i+1}. {packet.summary()}")
        
        if len(packets) > 5:
            print(f"   ... and {len(packets) - 5} more packets")
        
        print(f"\n3. Basic statistics:")
        total_size = sum(len(pkt) for pkt in packets)
        avg_size = total_size / len(packets) if packets else 0
        print(f"   Total size: {total_size} bytes")
        print(f"   Average packet size: {avg_size:.1f} bytes")
        
        # Protocol distribution
        from collections import Counter
        protocols = Counter()
        for packet in packets:
            if packet.haslayer('TCP'):
                protocols['TCP'] += 1
            elif packet.haslayer('UDP'):
                protocols['UDP'] += 1
            elif packet.haslayer('ICMP'):
                protocols['ICMP'] += 1
            else:
                protocols['Other'] += 1
        
        print(f"\n4. Protocol distribution:")
        for proto, count in protocols.most_common():
            percentage = (count / len(packets)) * 100
            print(f"   {proto}: {count} packets ({percentage:.1f}%)")
        
        print(f"\n✅ Basic sniffing completed!")
        print("   Next: Try analyze_pcap.py for file analysis")
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("   Make sure to install dependencies:")
        print("   pip install scapy matplotlib numpy")
    except KeyboardInterrupt:
        print("\n⚠️  Capture interrupted by user")
    except Exception as e:
        print(f"❌ Error: {e}")
        print("   Make sure you're running with proper privileges")

if __name__ == "__main__":
    main()