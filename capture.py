#!/usr/bin/env python3
"""
BGP Monitor with Database Storage
Captures BGP packets and stores prefixes, metadata, and packet information in SQLite database
"""

import sys
import sqlite3
import struct
import socket
import json
import os
from datetime import datetime, timedelta
from collections import defaultdict
from contextlib import contextmanager

try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP
except ImportError:
    print("Error: Scapy not installed. Install with: pip install scapy")
    sys.exit(1)

class BGPDatabaseMonitor:
    def __init__(self, interface=None, db_path="bgp_monitor.db"):
        self.interface = interface
        self.db_path = db_path
        self.session_count = 0

        # Initialize database
        self.init_database()

        # BGP message types and attributes
        self.bgp_message_types = {1: "OPEN", 2: "UPDATE", 3: "NOTIFICATION", 4: "KEEPALIVE"}
        self.path_attr_types = {
            1: "ORIGIN", 2: "AS_PATH", 3: "NEXT_HOP", 4: "MULTI_EXIT_DISC",
            5: "LOCAL_PREF", 6: "ATOMIC_AGGREGATE", 7: "AGGREGATOR", 8: "COMMUNITY"
        }
        self.origin_types = {0: "IGP", 1: "EGP", 2: "INCOMPLETE"}

        # Runtime statistics
        self.stats = {
            'packets_captured': 0,
            'updates_parsed': 0,
            'prefixes_stored': 0,
            'sessions_tracked': 0
        }

    def init_database(self):
        """Initialize SQLite database with required tables"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Table for BGP sessions
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS bgp_sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_key TEXT UNIQUE,
                        local_ip TEXT,
                        peer_ip TEXT,
                        local_port INTEGER,
                        peer_port INTEGER,
                        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        packet_count INTEGER DEFAULT 0,
                        status TEXT DEFAULT 'ACTIVE'
                    )
                ''')

                # Table for captured packets
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS bgp_packets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_id INTEGER,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        source_ip TEXT,
                        dest_ip TEXT,
                        source_port INTEGER,
                        dest_port INTEGER,
                        packet_length INTEGER,
                        tcp_flags TEXT,
                        bgp_message_type TEXT,
                        bgp_message_length INTEGER,
                        direction TEXT,
                        raw_payload BLOB,
                        FOREIGN KEY (session_id) REFERENCES bgp_sessions (id)
                    )
                ''')

                # Table for NLRI prefixes (announcements)
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS nlri_prefixes (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        packet_id INTEGER,
                        session_id INTEGER,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        prefix TEXT,
                        prefix_length INTEGER,
                        network_address TEXT,
                        action TEXT DEFAULT 'ANNOUNCE',
                        origin_as INTEGER,
                        as_path TEXT,
                        next_hop TEXT,
                        med INTEGER,
                        local_pref INTEGER,
                        communities TEXT,
                        path_attributes TEXT,
                        FOREIGN KEY (packet_id) REFERENCES bgp_packets (id),
                        FOREIGN KEY (session_id) REFERENCES bgp_sessions (id)
                    )
                ''')

                # Table for withdrawn prefixes
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS withdrawn_prefixes (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        packet_id INTEGER,
                        session_id INTEGER,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        prefix TEXT,
                        prefix_length INTEGER,
                        network_address TEXT,
                        FOREIGN KEY (packet_id) REFERENCES bgp_packets (id),
                        FOREIGN KEY (session_id) REFERENCES bgp_sessions (id)
                    )
                ''')

                # Table for path attributes details
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS path_attributes (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        packet_id INTEGER,
                        attribute_type INTEGER,
                        attribute_name TEXT,
                        attribute_value TEXT,
                        flags INTEGER,
                        length INTEGER,
                        FOREIGN KEY (packet_id) REFERENCES bgp_packets (id)
                    )
                ''')

                # Create indexes for better query performance
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_key ON bgp_sessions(session_key)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON bgp_packets(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_nlri_prefix ON nlri_prefixes(prefix)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_nlri_timestamp ON nlri_prefixes(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_withdrawn_prefix ON withdrawn_prefixes(prefix)')

                conn.commit()
                print(f"Database initialized: {self.db_path}")

        except sqlite3.Error as e:
            print(f"Database initialization error: {e}")
            sys.exit(1)

    @contextmanager
    def get_db_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Enable column access by name
        try:
            yield conn
        finally:
            conn.close()

    def get_or_create_session(self, src_ip, dst_ip, src_port, dst_port):
        """Get existing session or create new one"""
        # Create consistent session key
        if src_port == 179:
            local_ip, peer_ip = src_ip, dst_ip
            local_port, peer_port = src_port, dst_port
        else:
            local_ip, peer_ip = dst_ip, src_ip
            local_port, peer_port = dst_port, src_port

        session_key = f"{min(local_ip, peer_ip)}-{max(local_ip, peer_ip)}"

        with self.get_db_connection() as conn:
            cursor = conn.cursor()

            # Try to find existing session
            cursor.execute('''
                SELECT id FROM bgp_sessions WHERE session_key = ?
            ''', (session_key,))

            result = cursor.fetchone()
            if result:
                session_id = result[0]
                # Update last seen and packet count
                cursor.execute('''
                    UPDATE bgp_sessions 
                    SET last_seen = CURRENT_TIMESTAMP, packet_count = packet_count + 1
                    WHERE id = ?
                ''', (session_id,))
            else:
                # Create new session
                cursor.execute('''
                    INSERT INTO bgp_sessions (session_key, local_ip, peer_ip, local_port, peer_port)
                    VALUES (?, ?, ?, ?, ?)
                ''', (session_key, local_ip, peer_ip, local_port, peer_port))
                session_id = cursor.lastrowid
                self.stats['sessions_tracked'] += 1

            conn.commit()
            return session_id

    def store_packet(self, session_id, packet_info, raw_payload):
        """Store packet information in database"""
        with self.get_db_connection() as conn:
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO bgp_packets (
                    session_id, source_ip, dest_ip, source_port, dest_port,
                    packet_length, tcp_flags, bgp_message_type, bgp_message_length,
                    direction, raw_payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                session_id,
                packet_info['src_ip'],
                packet_info['dst_ip'],
                packet_info['src_port'],
                packet_info['dst_port'],
                packet_info['length'],
                packet_info['flags'],
                packet_info.get('bgp_type'),
                packet_info.get('bgp_length'),
                packet_info['direction'],
                raw_payload
            ))

            packet_id = cursor.lastrowid
            conn.commit()
            return packet_id

    def store_nlri_prefixes(self, packet_id, session_id, prefixes, path_attributes):
        """Store NLRI prefixes in database"""
        if not prefixes:
            return

        with self.get_db_connection() as conn:
            cursor = conn.cursor()

            # Extract common path attributes
            origin_as = None
            as_path_str = None
            next_hop = None
            med = None
            local_pref = None
            communities = None

            if path_attributes:
                if 'AS_PATH' in path_attributes and path_attributes['AS_PATH']:
                    as_path = path_attributes['AS_PATH']
                    if isinstance(as_path, list) and as_path:
                        origin_as = as_path[-1]
                        as_path_str = ' '.join(map(str, as_path))

                next_hop = path_attributes.get('NEXT_HOP')
                med = path_attributes.get('MED')
                local_pref = path_attributes.get('LOCAL_PREF')

                if 'COMMUNITY' in path_attributes:
                    communities = json.dumps(path_attributes['COMMUNITY'])

            # Store each prefix
            for prefix in prefixes:
                try:
                    # Parse prefix to get network address and length
                    network_addr, prefix_len = prefix.split('/')
                    prefix_len = int(prefix_len)

                    cursor.execute('''
                        INSERT INTO nlri_prefixes (
                            packet_id, session_id, prefix, prefix_length, network_address,
                            origin_as, as_path, next_hop, med, local_pref, communities,
                            path_attributes
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        packet_id, session_id, prefix, prefix_len, network_addr,
                        origin_as, as_path_str, next_hop, med, local_pref, communities,
                        json.dumps(path_attributes) if path_attributes else None
                    ))

                    self.stats['prefixes_stored'] += 1

                except Exception as e:
                    print(f"Error storing prefix {prefix}: {e}")

            conn.commit()

    def store_withdrawn_prefixes(self, packet_id, session_id, withdrawn_prefixes):
        """Store withdrawn prefixes in database"""
        if not withdrawn_prefixes:
            return

        with self.get_db_connection() as conn:
            cursor = conn.cursor()

            for prefix in withdrawn_prefixes:
                try:
                    network_addr, prefix_len = prefix.split('/')
                    prefix_len = int(prefix_len)

                    cursor.execute('''
                        INSERT INTO withdrawn_prefixes (
                            packet_id, session_id, prefix, prefix_length, network_address
                        ) VALUES (?, ?, ?, ?, ?)
                    ''', (packet_id, session_id, prefix, prefix_len, network_addr))

                except Exception as e:
                    print(f"Error storing withdrawn prefix {prefix}: {e}")

            conn.commit()

    def store_path_attributes(self, packet_id, path_attributes_raw):
        """Store detailed path attributes"""
        if not path_attributes_raw:
            return

        with self.get_db_connection() as conn:
            cursor = conn.cursor()

            for attr_type, attr_data in path_attributes_raw.items():
                attr_name = self.path_attr_types.get(attr_type, f"UNKNOWN_{attr_type}")
                attr_value = json.dumps(attr_data) if isinstance(attr_data, (list, dict)) else str(attr_data)

                cursor.execute('''
                    INSERT INTO path_attributes (
                        packet_id, attribute_type, attribute_name, attribute_value
                    ) VALUES (?, ?, ?, ?)
                ''', (packet_id, attr_type, attr_name, attr_value))

            conn.commit()

    def parse_nlri_prefix(self, data, offset):
        """Parse a single NLRI prefix"""
        if offset >= len(data):
            return None, offset

        prefix_len = data[offset]
        offset += 1
        prefix_bytes = (prefix_len + 7) // 8

        if offset + prefix_bytes > len(data):
            return None, offset

        prefix_data = data[offset:offset + prefix_bytes]
        offset += prefix_bytes

        # Pad to 4 bytes for IPv4
        padded_prefix = prefix_data + b'\x00' * (4 - len(prefix_data))

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

            segment_type = data[offset]
            segment_length = data[offset + 1]
            offset += 2

            segment_as_list = []
            for i in range(segment_length):
                if offset + 2 > len(data):
                    break
                as_num = struct.unpack('!H', data[offset:offset + 2])[0]
                segment_as_list.append(as_num)
                offset += 2

            if segment_type == 1:  # AS_SET
                as_path.append(f"({','.join(map(str, segment_as_list))})")
            else:  # AS_SEQUENCE
                as_path.extend(segment_as_list)

        return as_path

    def parse_path_attributes(self, data, attr_length):
        """Parse BGP path attributes"""
        attributes = {}
        offset = 0

        while offset < attr_length and offset < len(data):
            if offset + 2 > len(data):
                break

            attr_flags = data[offset]
            attr_type = data[offset + 1]
            offset += 2

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

            try:
                if attr_type == 1:  # ORIGIN
                    if len(attr_value) >= 1:
                        attributes['ORIGIN'] = self.origin_types.get(attr_value[0], attr_value[0])

                elif attr_type == 2:  # AS_PATH
                    attributes['AS_PATH'] = self.parse_as_path(attr_value)

                elif attr_type == 3:  # NEXT_HOP
                    if len(attr_value) >= 4:
                        attributes['NEXT_HOP'] = socket.inet_ntoa(attr_value[:4])

                elif attr_type == 4:  # MULTI_EXIT_DISC
                    if len(attr_value) >= 4:
                        attributes['MED'] = struct.unpack('!I', attr_value[:4])[0]

                elif attr_type == 5:  # LOCAL_PREF
                    if len(attr_value) >= 4:
                        attributes['LOCAL_PREF'] = struct.unpack('!I', attr_value[:4])[0]

                elif attr_type == 8:  # COMMUNITY
                    communities = []
                    for i in range(0, len(attr_value), 4):
                        if i + 4 <= len(attr_value):
                            comm = struct.unpack('!I', attr_value[i:i+4])[0]
                            communities.append(f"{(comm >> 16) & 0xFFFF}:{comm & 0xFFFF}")
                    attributes['COMMUNITY'] = communities

            except Exception as e:
                print(f"Error parsing attribute {attr_type}: {e}")

        return attributes

    def parse_bgp_update(self, payload):
        """Parse BGP UPDATE message"""
        try:
            if len(payload) < 23:
                return None

            offset = 19  # Skip BGP header

            # Withdrawn Routes
            withdrawn_len = struct.unpack('!H', payload[offset:offset + 2])[0]
            offset += 2

            withdrawn_routes = []
            withdrawn_end = offset + withdrawn_len

            while offset < withdrawn_end and offset < len(payload):
                prefix, offset = self.parse_nlri_prefix(payload, offset)
                if prefix:
                    withdrawn_routes.append(prefix)
                else:
                    break

            offset = withdrawn_end

            if offset + 2 > len(payload):
                return None

            # Path Attributes
            path_attr_len = struct.unpack('!H', payload[offset:offset + 2])[0]
            offset += 2

            path_attributes = {}
            if path_attr_len > 0 and offset + path_attr_len <= len(payload):
                path_attributes = self.parse_path_attributes(
                    payload[offset:offset + path_attr_len], path_attr_len
                )

            offset += path_attr_len

            # NLRI
            nlri_prefixes = []
            while offset < len(payload):
                prefix, offset = self.parse_nlri_prefix(payload, offset)
                if prefix:
                    nlri_prefixes.append(prefix)
                else:
                    break

            return {
                'withdrawn_routes': withdrawn_routes,
                'path_attributes': path_attributes,
                'nlri_prefixes': nlri_prefixes
            }

        except Exception as e:
            print(f"Error parsing BGP UPDATE: {e}")
            return None

    def analyze_bgp_packet(self, packet):
        """Analyze and extract BGP packet information"""
        try:
            ip_layer = packet[IP]
            tcp_layer = packet[TCP]

            packet_info = {
                'src_ip': ip_layer.src,
                'dst_ip': ip_layer.dst,
                'src_port': tcp_layer.sport,
                'dst_port': tcp_layer.dport,
                'length': len(packet),
                'flags': '',
                'direction': 'FROM' if tcp_layer.sport == 179 else 'TO'
            }

            # TCP flags
            flags = tcp_layer.flags
            flag_parts = []
            if flags & 0x02: flag_parts.append("SYN")
            if flags & 0x10: flag_parts.append("ACK")
            if flags & 0x01: flag_parts.append("FIN")
            if flags & 0x04: flag_parts.append("RST")
            if flags & 0x08: flag_parts.append("PSH")
            packet_info['flags'] = ' '.join(flag_parts)

            return packet_info

        except Exception as e:
            return {'error': f"Error analyzing packet: {e}"}

    def packet_handler(self, packet):
        """Main packet handler"""
        try:
            self.stats['packets_captured'] += 1

            if packet.haslayer(TCP) and packet.haslayer(IP):
                tcp_layer = packet[TCP]

                # Check for BGP traffic
                if tcp_layer.sport == 179 or tcp_layer.dport == 179:
                    packet_info = self.analyze_bgp_packet(packet)

                    if 'error' in packet_info:
                        return

                    # Get or create session
                    session_id = self.get_or_create_session(
                        packet_info['src_ip'], packet_info['dst_ip'],
                        packet_info['src_port'], packet_info['dst_port']
                    )

                    # Check for BGP payload
                    if tcp_layer.payload:
                        payload = bytes(tcp_layer.payload)

                        # Check if it's a valid BGP message
                        if len(payload) >= 19 and payload[:16] == b'\xff' * 16:
                            msg_type = payload[18] if len(payload) > 18 else 0
                            msg_length = struct.unpack('!H', payload[16:18])[0] if len(payload) >= 18 else 0

                            packet_info['bgp_type'] = self.bgp_message_types.get(msg_type, f"UNKNOWN_{msg_type}")
                            packet_info['bgp_length'] = msg_length

                            # Store packet information
                            packet_id = self.store_packet(session_id, packet_info, payload)

                            # Parse UPDATE messages
                            if msg_type == 2:  # UPDATE
                                self.stats['updates_parsed'] += 1
                                update_data = self.parse_bgp_update(payload)

                                if update_data:
                                    # Store NLRI prefixes
                                    if update_data['nlri_prefixes']:
                                        self.store_nlri_prefixes(
                                            packet_id, session_id,
                                            update_data['nlri_prefixes'],
                                            update_data['path_attributes']
                                        )

                                    # Store withdrawn prefixes
                                    if update_data['withdrawn_routes']:
                                        self.store_withdrawn_prefixes(
                                            packet_id, session_id,
                                            update_data['withdrawn_routes']
                                        )

                                    # Display real-time info
                                    self.display_update_summary(update_data, packet_info)

                            else:
                                # Store non-UPDATE BGP messages
                                print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                                      f"{packet_info['bgp_type']} from {packet_info['src_ip']}")

                        else:
                            # Store non-BGP TCP packet on port 179
                            packet_id = self.store_packet(session_id, packet_info, payload)

        except Exception as e:
            print(f"Error in packet handler: {e}")

    def display_update_summary(self, update_data, packet_info):
        """Display real-time UPDATE summary"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        src_ip = packet_info['src_ip']

        nlri_count = len(update_data['nlri_prefixes'])
        withdrawn_count = len(update_data['withdrawn_routes'])

        if nlri_count > 0:
            print(f"[{timestamp}] UPDATE from {src_ip}: +{nlri_count} prefixes")
            for prefix in update_data['nlri_prefixes'][:3]:  # Show first 3
                print(f"  + {prefix}")
            if nlri_count > 3:
                print(f"  ... and {nlri_count - 3} more")

        if withdrawn_count > 0:
            print(f"[{timestamp}] UPDATE from {src_ip}: -{withdrawn_count} withdrawals")
            for prefix in update_data['withdrawn_routes'][:3]:
                print(f"  - {prefix}")
            if withdrawn_count > 3:
                print(f"  ... and {withdrawn_count - 3} more")

    def display_statistics(self):
        """Display monitoring statistics"""
        print("\n" + "=" * 60)
        print("BGP MONITORING STATISTICS")
        print("=" * 60)
        print(f"Packets captured: {self.stats['packets_captured']}")
        print(f"UPDATE messages parsed: {self.stats['updates_parsed']}")
        print(f"Prefixes stored: {self.stats['prefixes_stored']}")
        print(f"Sessions tracked: {self.stats['sessions_tracked']}")

        # Database statistics
        with self.get_db_connection() as conn:
            cursor = conn.cursor()

            cursor.execute('SELECT COUNT(*) FROM bgp_sessions')
            total_sessions = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM bgp_packets')
            total_packets = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM nlri_prefixes')
            total_nlri = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM withdrawn_prefixes')
            total_withdrawn = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(DISTINCT prefix) FROM nlri_prefixes')
            unique_prefixes = cursor.fetchone()[0]

            print(f"\nDatabase Statistics:")
            print(f"Total sessions: {total_sessions}")
            print(f"Total packets stored: {total_packets}")
            print(f"NLRI announcements: {total_nlri}")
            print(f"Prefix withdrawals: {total_withdrawn}")
            print(f"Unique prefixes: {unique_prefixes}")

    def query_database(self, query_type="recent_prefixes", limit=10):
        """Query database for analysis"""
        with self.get_db_connection() as conn:
            cursor = conn.cursor()

            if query_type == "recent_prefixes":
                cursor.execute('''
                    SELECT prefix, next_hop, origin_as, timestamp 
                    FROM nlri_prefixes 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (limit,))

                results = cursor.fetchall()
                print(f"\nRecent {limit} NLRI Prefixes:")
                print("-" * 50)
                for row in results:
                    print(f"{row[0]:<18} NH:{row[1]:<15} AS:{row[2]:<8} {row[3]}")

            elif query_type == "top_origins":
                cursor.execute('''
                    SELECT origin_as, COUNT(*) as count
                    FROM nlri_prefixes 
                    WHERE origin_as IS NOT NULL
                    GROUP BY origin_as 
                    ORDER BY count DESC 
                    LIMIT ?
                ''', (limit,))

                results = cursor.fetchall()
                print(f"\nTop {limit} Origin AS:")
                print("-" * 30)
                for row in results:
                    print(f"AS{row[0]}: {row[1]} prefixes")

            elif query_type == "active_sessions":
                cursor.execute('''
                    SELECT local_ip, peer_ip, packet_count, 
                           datetime(first_seen) as first_seen,
                           datetime(last_seen) as last_seen
                    FROM bgp_sessions 
                    ORDER BY last_seen DESC 
                    LIMIT ?
                ''', (limit,))

                results = cursor.fetchall()
                print(f"\nActive BGP Sessions:")
                print("-" * 50)
                for row in results:
                    print(f"{row[0]} <-> {row[1]} ({row[2]} packets)")
                    print(f"  First: {row[3]}, Last: {row[4]}")

    def start_monitoring(self):
        """Start BGP monitoring with database storage"""
        print("BGP Monitor with Database Storage")
        print("=" * 60)
        print(f"Database: {self.db_path}")
        print("Monitoring BGP traffic and storing to database...")
        print("Press Ctrl+C to stop and view statistics\n")

        try:
            sniff(
                iface=self.interface,
                filter="tcp port 179",
                prn=self.packet_handler,
                store=0
            )
        except KeyboardInterrupt:
            print("\nStopping BGP monitor...")
        except Exception as e:
            print(f"Error during monitoring: {e}")
        finally:
            self.display_statistics()
            self.query_database("recent_prefixes", 5)
            self.query_database("top_origins", 5)
            self.query_database("active_sessions", 5)

def main():
    import argparse

    parser = argparse.ArgumentParser(description="BGP Monitor with Database Storage")
    parser.add_argument('-i', '--interface', help='Network interface to monitor')
    parser.add_argument('-d', '--database', default='bgp_monitor.db',
                        help='SQLite database file path')
    parser.add_argument('--query', choices=['recent_prefixes', 'top_origins', 'active_sessions'],
                        help='Query database without monitoring')

    args = parser.parse_args()

    if args.query:
        # Query mode
        monitor = BGPDatabaseMonitor(db_path=args.database)
        monitor.query_database(args.query, 20)
        return

    if os.getpid() == 0:
        monitor = BGPDatabaseMonitor(interface=args.interface, db_path=args.database)
        monitor.start_monitoring()
        return

    # Check for root privileges
    print("Warning: Root privileges required for packet capture")
    print("Try: sudo python3 bgp_database_monitor.py")


if __name__ == "__main__":
    main()