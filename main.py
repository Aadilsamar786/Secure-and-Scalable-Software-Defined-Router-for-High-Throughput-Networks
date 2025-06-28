#!/usr/bin/env python3
"""
BGP Network Interface Monitor
Real-time monitoring and analysis of BGP traffic using Scapy
"""
import os
import sys
import time
import threading
from datetime import datetime
from collections import defaultdict, deque
import argparse

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
except ImportError:
    print("Error: Scapy not installed. Install with: pip install scapy")
    sys.exit(1)

class BGPMonitor:
    def __init__(self, interface=None, output_file=None):
        self.interface = interface
        self.output_file = output_file
        self.bgp_sessions = {}
        self.packet_count = 0
        self.start_time = time.time()
        self.packet_buffer = deque(maxlen=1000)  # Store last 1000 packets
        self.statistics = {
            'total_packets': 0,
            'bgp_packets': 0,
            'tcp_syn': 0,
            'tcp_fin': 0,
            'tcp_rst': 0,
            'sessions': defaultdict(int)
        }

        # BGP Message Types
        self.bgp_message_types = {
            1: "OPEN",
            2: "UPDATE",
            3: "NOTIFICATION",
            4: "KEEPALIVE"
        }

        self.running = True

    def get_available_interfaces(self):
        """Get list of available network interfaces"""
        try:
            interfaces = get_if_list()
            print("Available Network Interfaces:")
            print("-" * 40)
            for i, iface in enumerate(interfaces):
                try:
                    ip = get_if_addr(iface)
                    print(f"{i+1:2d}. {iface:<15} IP: {ip}")
                except:
                    print(f"{i+1:2d}. {iface:<15} IP: N/A")
            return interfaces
        except Exception as e:
            print(f"Error getting interfaces: {e}")
            return []

    def setup_monitoring(self):
        """Setup network interface monitoring"""
        print("=" * 60)
        print("BGP NETWORK INTERFACE MONITOR")
        print("=" * 60)
        print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        if not self.interface:
            interfaces = self.get_available_interfaces()
            if not interfaces:
                print("No interfaces available")
                return False

            while True:
                try:
                    choice = input(f"\nSelect interface (1-{len(interfaces)}) or 'any' for all: ").strip()
                    if choice.lower() == 'any':
                        self.interface = None
                        break
                    else:
                        idx = int(choice) - 1
                        if 0 <= idx < len(interfaces):
                            self.interface = interfaces[idx]
                            break
                        else:
                            print("Invalid selection")
                except ValueError:
                    print("Please enter a valid number")

        print(f"\nMonitoring Interface: {self.interface if self.interface else 'ALL'}")
        print("Filtering for BGP traffic (TCP port 179)")
        print("Press Ctrl+C to stop monitoring\n")

        return True

    def analyze_bgp_packet(self, packet):
        """Analyze BGP packet content"""
        try:
            ip_layer = packet[IP]
            tcp_layer = packet[TCP]

            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport

            # Determine direction (which side is BGP port 179)
            if src_port == 179:
                bgp_peer = src_ip
                direction = "FROM"
            else:
                bgp_peer = dst_ip
                direction = "TO"

            # Session tracking
            session_key = f"{min(src_ip, dst_ip)}-{max(src_ip, dst_ip)}"
            self.statistics['sessions'][session_key] += 1

            # TCP flags analysis
            flags = tcp_layer.flags
            flag_str = ""
            if flags & 0x02: flag_str += "SYN "
            if flags & 0x10: flag_str += "ACK "
            if flags & 0x01: flag_str += "FIN "
            if flags & 0x04: flag_str += "RST "
            if flags & 0x08: flag_str += "PSH "

            # Update statistics
            if flags & 0x02: self.statistics['tcp_syn'] += 1
            if flags & 0x01: self.statistics['tcp_fin'] += 1
            if flags & 0x04: self.statistics['tcp_rst'] += 1

            packet_info = {
                'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'direction': direction,
                'flags': flag_str.strip(),
                'length': len(packet),
                'session': session_key
            }

            # Try to parse BGP message if payload exists
            if tcp_layer.payload:
                self.parse_bgp_message(packet_info, bytes(tcp_layer.payload))

            return packet_info

        except Exception as e:
            return {'error': f"Error analyzing packet: {e}"}

    def parse_bgp_message(self, packet_info, payload):
        """Parse BGP message from TCP payload"""
        try:
            if len(payload) < 19:  # BGP header is 19 bytes
                return

            # BGP Header: 16 bytes marker + 2 bytes length + 1 byte type
            marker = payload[:16]
            if marker != b'\xff' * 16:  # BGP marker check
                return

            length = int.from_bytes(payload[16:18], 'big')
            msg_type = payload[18]

            if msg_type in self.bgp_message_types:
                packet_info['bgp_type'] = self.bgp_message_types[msg_type]
                packet_info['bgp_length'] = length

                # Additional parsing based on message type
                if msg_type == 1:  # OPEN
                    if len(payload) >= 29:
                        version = payload[19]
                        as_num = int.from_bytes(payload[20:22], 'big')
                        hold_time = int.from_bytes(payload[22:24], 'big')
                        packet_info['bgp_details'] = f"Ver:{version} AS:{as_num} Hold:{hold_time}s"

                elif msg_type == 2:  # UPDATE
                    packet_info['bgp_details'] = "Route Update"

                elif msg_type == 3:  # NOTIFICATION
                    if len(payload) >= 21:
                        error_code = payload[19]
                        error_subcode = payload[20]
                        packet_info['bgp_details'] = f"Error:{error_code}.{error_subcode}"

                elif msg_type == 4:  # KEEPALIVE
                    packet_info['bgp_details'] = "Keepalive"

        except Exception as e:
            packet_info['bgp_parse_error'] = str(e)

    def packet_handler(self, packet):
        """Handle captured packets"""
        try:
            self.statistics['total_packets'] += 1

            # Check if it's a BGP packet (TCP port 179)
            if packet.haslayer(TCP) and packet.haslayer(IP):
                tcp_layer = packet[TCP]
                if tcp_layer.sport == 179 or tcp_layer.dport == 179:
                    self.statistics['bgp_packets'] += 1

                    # Analyze the BGP packet
                    packet_info = self.analyze_bgp_packet(packet)
                    self.packet_buffer.append(packet_info)

                    # Display packet information
                    self.display_packet_info(packet_info)

                    # Write to file if specified
                    if self.output_file:
                        self.write_to_file(packet_info)

        except Exception as e:
            print(f"Error processing packet: {e}")

    def display_packet_info(self, packet_info):
        """Display packet information in real-time"""
        if 'error' in packet_info:
            print(f"[{packet_info.get('timestamp', 'N/A')}] ERROR: {packet_info['error']}")
            return

        timestamp = packet_info['timestamp']
        src_ip = packet_info['src_ip']
        dst_ip = packet_info['dst_ip']
        direction = packet_info['direction']
        flags = packet_info['flags']
        length = packet_info['length']

        print(f"[{timestamp}] {src_ip}:{packet_info['src_port']} -> {dst_ip}:{packet_info['dst_port']}")
        print(f"    Direction: {direction} BGP  Flags: [{flags}]  Length: {length} bytes")

        if 'bgp_type' in packet_info:
            bgp_type = packet_info['bgp_type']
            bgp_length = packet_info['bgp_length']
            print(f"    BGP Message: {bgp_type} (Length: {bgp_length})")

            if 'bgp_details' in packet_info:
                print(f"    Details: {packet_info['bgp_details']}")

        if 'bgp_parse_error' in packet_info:
            print(f"    Parse Warning: {packet_info['bgp_parse_error']}")

        print("-" * 50)

    def write_to_file(self, packet_info):
        """Write packet information to file"""
        try:
            with open(self.output_file, 'a') as f:
                f.write(f"{packet_info}\n")
        except Exception as e:
            print(f"Error writing to file: {e}")

    def display_statistics(self):
        """Display monitoring statistics"""
        runtime = time.time() - self.start_time
        print("\n" + "=" * 60)
        print("MONITORING STATISTICS")
        print("=" * 60)
        print(f"Runtime: {runtime:.1f} seconds")
        print(f"Total Packets Captured: {self.statistics['total_packets']}")
        print(f"BGP Packets: {self.statistics['bgp_packets']}")
        print(f"TCP SYN: {self.statistics['tcp_syn']}")
        print(f"TCP FIN: {self.statistics['tcp_fin']}")
        print(f"TCP RST: {self.statistics['tcp_rst']}")

        if self.statistics['sessions']:
            print(f"\nBGP Sessions Detected: {len(self.statistics['sessions'])}")
            for session, count in self.statistics['sessions'].items():
                print(f"  {session}: {count} packets")

        if runtime > 0:
            pps = self.statistics['total_packets'] / runtime
            print(f"\nAverage Packet Rate: {pps:.2f} packets/second")

    def start_monitoring(self):
        """Start the BGP monitoring"""
        if not self.setup_monitoring():
            return

        try:
            # Start packet capture
            print("Starting packet capture...")
            sniff(
                iface=self.interface,
                filter="tcp port 179",  # BGP traffic filter
                prn=self.packet_handler,
                store=0  # Don't store packets in memory
            )

        except KeyboardInterrupt:
            print("\nStopping monitor...")
            self.running = False

        except Exception as e:
            print(f"Error during monitoring: {e}")

        finally:
            self.display_statistics()

def main():
    parser = argparse.ArgumentParser(description="BGP Network Interface Monitor")
    parser.add_argument('-i', '--interface', help='Network interface to monitor')
    parser.add_argument('-o', '--output', help='Output file for packet logs')
    parser.add_argument('--list-interfaces', action='store_true',
                        help='List available network interfaces')

    args = parser.parse_args()

    if args.list_interfaces:
        monitor = BGPMonitor()
        monitor.get_available_interfaces()
        return

    # Check if running as root/admin (required for packet capture)
    if os.getpid() != 0:
        print("Warning: This script may require root privileges for packet capture")
        print("Try running with: sudo python3 bgp_monitor.py")

    monitor = BGPMonitor(interface=args.interface, output_file=args.output)
    monitor.start_monitoring()

if __name__ == "__main__":
    main()