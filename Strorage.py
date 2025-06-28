#!/usr/bin/env python3
"""
BGP UPDATE Packet Parser
Captures and parses BGP UPDATE messages to extract NLRI prefixes
"""

import sys
import struct
import socket
import ipaddress
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP
except ImportError:
    print("Error: Scapy not installed. Install with: pip install scapy")
    sys.exit(1)

class BGPUpdateParser:
    def __init__(self, interface=None):
        self.interface = interface
        self.update_count = 0
        self.nlri_prefixes = []
        self.withdrawn_prefixes = []
        self.path_attributes = []
        self.statistics = {
            'total_updates': 0,
            'nlri_announcements': 0,
            'withdrawals': 0,
            'unique_prefixes': set(),
            'origin_as': defaultdict(int),
            'next_hops': defaultdict(int)
        }

        # BGP Path Attribute Types
        self.path_attr_types = {
            1: "ORIGIN",
            2: "AS_PATH",
            3: "NEXT_HOP",
            4: "MULTI_EXIT_DISC",
            5: "LOCAL_PREF",
            6: "ATOMIC_AGGREGATE",
            7: "AGGREGATOR",
            8: "COMMUNITY",
            14: "MP_REACH_NLRI",
            15: "MP_UNREACH_NLRI"
        }

        # BGP Origin Types
        self.origin_types = {0: "IGP", 1: "EGP", 2: "INCOMPLETE"}

    def parse_length_prefix(self, data, offset):
        """Parse a length-prefixed field (used for AS_PATH segments)"""
        if offset >= len(data):
            return None, offset

        length = data[offset]
        offset += 1

        if offset + length > len(data):
            return None, offset

        value = data[offset:offset + length]
        offset += length

        return value, offset

    def parse_nlri_prefix(self, data, offset):
        """Parse a single NLRI prefix"""
        if offset >= len(data):
            return None, offset

        # Get prefix length in bits
        prefix_len = data[offset]
        offset += 1

        # Calculate number of bytes needed for the prefix
        prefix_bytes = (prefix_len + 7) // 8

        if offset + prefix_bytes > len(data):
            return None, offset

        # Extract prefix bytes and pad to 4 bytes for IPv4
        prefix_data = data[offset:offset + prefix_bytes]
        offset += prefix_bytes

        # Pad to 4 bytes for IPv4 address
        padded_prefix = prefix_data + b'\x00' * (4 - len(prefix_data))

        # Convert to IP address
        try:
            ip_int = struct.unpack('!I', padded_prefix)[0]
            ip_addr = socket.inet_ntoa(struct.pack('!I', ip_int))
            prefix = f"{ip_addr}/{prefix_len}"
            return prefix, offset
        except:
            return None, offset

    def parse_as_path(self, data):
        """Parse AS_PATH attribute"""
        as_path = []
        offset = 0

        while offset < len(data):
            if offset + 2 > len(data):
                break

            # AS_PATH segment type and length
            segment_type = data[offset]
            segment_length = data[offset + 1]
            offset += 2

            segment_as_list = []

            # Parse AS numbers (assuming 2-byte AS numbers for simplicity)
            for i in range(segment_length):
                if offset + 2 > len(data):
                    break
                as_num = struct.unpack('!H', data[offset:offset + 2])[0]
                segment_as_list.append(as_num)
                offset += 2

            # Segment types: 1=AS_SET, 2=AS_SEQUENCE
            if segment_type == 1:
                as_path.append(f"({','.join(map(str, segment_as_list))})")
            else:
                as_path.extend(segment_as_list)

        return as_path

    def parse_path_attributes(self, data, attr_length):
        """Parse BGP path attributes"""
        attributes = {}
        offset = 0

        while offset < attr_length and offset < len(data):
            if offset + 2 > len(data):
                break

            # Attribute flags and type
            attr_flags = data[offset]
            attr_type = data[offset + 1]
            offset += 2

            # Check if extended length flag is set
            if attr_flags & 0x10:  # Extended Length
                if offset + 2 > len(data):
                    break
                attr_len = struct.unpack('!H', data[offset:offset + 2])[0]
                offset += 2
            else:
                if offset + 1 > len(data):
                    break
                attr_len = data[offset]
                offset += 1

            if offset + attr_len > len(data):
                break

            attr_value = data[offset:offset + attr_len]
            offset += attr_len

            # Parse specific attribute types
            attr_name = self.path_attr_types.get(attr_type, f"UNKNOWN_{attr_type}")

            try:
                if attr_type == 1:  # ORIGIN
                    if len(attr_value) >= 1:
                        origin_val = attr_value[0]
                        attributes['ORIGIN'] = self.origin_types.get(origin_val, origin_val)

                elif attr_type == 2:  # AS_PATH
                    attributes['AS_PATH'] = self.parse_as_path(attr_value)

                elif attr_type == 3:  # NEXT_HOP
                    if len(attr_value) >= 4:
                        next_hop = socket.inet_ntoa(attr_value[:4])
                        attributes['NEXT_HOP'] = next_hop
                        self.statistics['next_hops'][next_hop] += 1

                elif attr_type == 4:  # MULTI_EXIT_DISC
                    if len(attr_value) >= 4:
                        med = struct.unpack('!I', attr_value[:4])[0]
                        attributes['MED'] = med

                elif attr_type == 5:  # LOCAL_PREF
                    if len(attr_value) >= 4:
                        local_pref = struct.unpack('!I', attr_value[:4])[0]
                        attributes['LOCAL_PREF'] = local_pref

                elif attr_type == 8:  # COMMUNITY
                    communities = []
                    for i in range(0, len(attr_value), 4):
                        if i + 4 <= len(attr_value):
                            comm = struct.unpack('!I', attr_value[i:i+4])[0]
                            communities.append(f"{(comm >> 16) & 0xFFFF}:{comm & 0xFFFF}")
                    attributes['COMMUNITY'] = communities

                else:
                    attributes[attr_name] = f"<{len(attr_value)} bytes>"

            except Exception as e:
                attributes[attr_name] = f"<parse_error: {e}>"

        return attributes

    def parse_bgp_update(self, payload):
        """Parse BGP UPDATE message"""
        try:
            if len(payload) < 23:  # BGP header (19) + minimum update fields (4)
                return None

            # Skip BGP header (19 bytes)
            offset = 19

            # Withdrawn Routes Length (2 bytes)
            withdrawn_len = struct.unpack('!H', payload[offset:offset + 2])[0]
            offset += 2

            # Parse Withdrawn Routes
            withdrawn_routes = []
            withdrawn_end = offset + withdrawn_len

            while offset < withdrawn_end and offset < len(payload):
                prefix, offset = self.parse_nlri_prefix(payload, offset)
                if prefix:
                    withdrawn_routes.append(prefix)
                    self.statistics['unique_prefixes'].add(prefix)
                else:
                    break

            # Skip any remaining withdrawn routes data
            offset = withdrawn_end

            if offset + 2 > len(payload):
                return None

            # Path Attributes Length (2 bytes)
            path_attr_len = struct.unpack('!H', payload[offset:offset + 2])[0]
            offset += 2

            # Parse Path Attributes
            path_attributes = {}
            if path_attr_len > 0 and offset + path_attr_len <= len(payload):
                path_attributes = self.parse_path_attributes(
                    payload[offset:offset + path_attr_len], path_attr_len
                )

            offset += path_attr_len

            # Parse NLRI (Network Layer Reachability Information)
            nlri_prefixes = []
            while offset < len(payload):
                prefix, offset = self.parse_nlri_prefix(payload, offset)
                if prefix:
                    nlri_prefixes.append(prefix)
                    self.statistics['unique_prefixes'].add(prefix)
                else:
                    break

            # Update statistics
            if nlri_prefixes:
                self.statistics['nlri_announcements'] += len(nlri_prefixes)
            if withdrawn_routes:
                self.statistics['withdrawals'] += len(withdrawn_routes)

            # Track origin AS
            if 'AS_PATH' in path_attributes and path_attributes['AS_PATH']:
                origin_as = path_attributes['AS_PATH'][-1] if isinstance(path_attributes['AS_PATH'], list) else None
                if origin_as:
                    self.statistics['origin_as'][origin_as] += 1

            return {
                'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                'withdrawn_routes': withdrawn_routes,
                'path_attributes': path_attributes,
                'nlri_prefixes': nlri_prefixes,
                'withdrawn_count': len(withdrawn_routes),
                'nlri_count': len(nlri_prefixes)
            }

        except Exception as e:
            return {'error': f"Parse error: {e}"}

    def display_update_info(self, update_info):
        """Display parsed BGP UPDATE information"""
        if 'error' in update_info:
            print(f"[{update_info.get('timestamp', 'N/A')}] {update_info['error']}")
            return

        timestamp = update_info['timestamp']
        self.update_count += 1

        print(f"\n[{timestamp}] BGP UPDATE #{self.update_count}")
        print("=" * 60)

        # Display withdrawn routes
        if update_info['withdrawn_routes']:
            print(f"WITHDRAWN ROUTES ({update_info['withdrawn_count']}):")
            for prefix in update_info['withdrawn_routes']:
                print(f"  - {prefix}")
            print()

        # Display path attributes
        if update_info['path_attributes']:
            print("PATH ATTRIBUTES:")
            for attr_name, attr_value in update_info['path_attributes'].items():
                if isinstance(attr_value, list):
                    if attr_name == 'AS_PATH':
                        as_path_str = ' '.join(map(str, attr_value))
                        print(f"  {attr_name}: {as_path_str}")
                    else:
                        print(f"  {attr_name}: {', '.join(map(str, attr_value))}")
                else:
                    print(f"  {attr_name}: {attr_value}")
            print()

        # Display NLRI prefixes (announcements)
        if update_info['nlri_prefixes']:
            print(f"NLRI ANNOUNCEMENTS ({update_info['nlri_count']}):")
            for prefix in update_info['nlri_prefixes']:
                print(f"  + {prefix}")

            # Store for analysis
            self.nlri_prefixes.extend(update_info['nlri_prefixes'])

        if update_info['withdrawn_routes']:
            self.withdrawn_prefixes.extend(update_info['withdrawn_routes'])

        print("-" * 60)

    def packet_handler(self, packet):
        """Handle captured BGP packets"""
        try:
            if packet.haslayer(TCP) and packet.haslayer(IP):
                tcp_layer = packet[TCP]

                # Check if it's BGP traffic (port 179)
                if tcp_layer.sport == 179 or tcp_layer.dport == 179:
                    # Check if packet has payload
                    if tcp_layer.payload:
                        payload = bytes(tcp_layer.payload)

                        # Check if it's a BGP UPDATE message
                        if len(payload) >= 19:  # BGP header length
                            # Check BGP marker
                            if payload[:16] == b'\xff' * 16:
                                msg_type = payload[18] if len(payload) > 18 else 0

                                # Process only UPDATE messages (type 2)
                                if msg_type == 2:
                                    self.statistics['total_updates'] += 1
                                    update_info = self.parse_bgp_update(payload)
                                    if update_info:
                                        self.display_update_info(update_info)

        except Exception as e:
            print(f"Error processing packet: {e}")

    def display_summary(self):
        """Display summary statistics"""
        print("\n" + "=" * 60)
        print("BGP UPDATE PARSING SUMMARY")
        print("=" * 60)
        print(f"Total UPDATE messages parsed: {self.statistics['total_updates']}")
        print(f"NLRI announcements: {self.statistics['nlri_announcements']}")
        print(f"Prefix withdrawals: {self.statistics['withdrawals']}")
        print(f"Unique prefixes seen: {len(self.statistics['unique_prefixes'])}")

        if self.statistics['origin_as']:
            print(f"\nTop Origin AS numbers:")
            sorted_as = sorted(self.statistics['origin_as'].items(),
                               key=lambda x: x[1], reverse=True)[:10]
            for as_num, count in sorted_as:
                print(f"  AS{as_num}: {count} announcements")

        if self.statistics['next_hops']:
            print(f"\nNext Hop addresses:")
            for next_hop, count in self.statistics['next_hops'].items():
                print(f"  {next_hop}: {count} times")

        if self.statistics['unique_prefixes']:
            print(f"\nSample prefixes:")
            sample_prefixes = list(self.statistics['unique_prefixes'])[:10]
            for prefix in sample_prefixes:
                print(f"  {prefix}")
            if len(self.statistics['unique_prefixes']) > 10:
                print(f"  ... and {len(self.statistics['unique_prefixes']) - 10} more")

    def start_monitoring(self):
        """Start BGP UPDATE monitoring"""
        print("BGP UPDATE Packet Parser")
        print("=" * 60)
        print("Monitoring for BGP UPDATE messages (type 2)")
        print("Extracting NLRI prefixes and withdrawn routes")
        print("Press Ctrl+C to stop and view summary\n")

        try:
            sniff(
                iface=self.interface,
                filter="tcp port 179",
                prn=self.packet_handler,
                store=0
            )
        except KeyboardInterrupt:
            print("\nStopping BGP UPDATE parser...")
        except Exception as e:
            print(f"Error during monitoring: {e}")
        finally:
            self.display_summary()

def main():
    import argparse

    parser = argparse.ArgumentParser(description="BGP UPDATE Packet Parser")
    parser.add_argument('-i', '--interface', help='Network interface to monitor')

    args = parser.parse_args()

    # Check for root privileges
    if os.getpid() != 0:
        print("Warning: Root privileges may be required for packet capture")
        print("Try: sudo python3 bgp_update_parser.py")

    parser = BGPUpdateParser(interface=args.interface)
    parser.start_monitoring()

if __name__ == "__main__":
    main()