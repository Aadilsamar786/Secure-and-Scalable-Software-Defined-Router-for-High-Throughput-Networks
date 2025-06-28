from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import threading
import time
import json
import logging
from datetime import datetime
from collections import defaultdict, deque
import scapy.all as scapy
from scapy.layers.inet import IP, TCP
import struct
import socket
import random

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'bgp_sniffer_secret_key'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Global state
sniffer_active = False
sniffer_thread = None
bgp_routes = {}
traffic_stats = {
    'total_packets': 0,
    'bgp_packets': 0,
    'encrypted_packets': 0,
    'forwarded_packets': 0
}
packet_logs = deque(maxlen=1000)  # Keep last 1000 packets
real_time_data = deque(maxlen=100)  # For charts
route_table = {}

class BGPSniffer:
    def __init__(self):
        self.running = False
        self.interface = None

    def parse_bgp_packet(self, packet):
        """Parse BGP packet and extract route information"""
        try:
            if packet.haslayer(TCP) and (packet[TCP].sport == 179 or packet[TCP].dport == 179):
                # BGP uses TCP port 179
                bgp_data = bytes(packet[TCP].payload)
                if len(bgp_data) >= 19:  # Minimum BGP header size
                    # Basic BGP header parsing
                    marker = bgp_data[:16]
                    length = struct.unpack('!H', bgp_data[16:18])[0]
                    msg_type = bgp_data[18]

                    return {
                        'type': self.get_bgp_message_type(msg_type),
                        'length': length,
                        'src': packet[IP].src,
                        'dst': packet[IP].dst,
                        'timestamp': datetime.now().isoformat()
                    }
        except Exception as e:
            logger.error(f"Error parsing BGP packet: {e}")
        return None

    def get_bgp_message_type(self, msg_type):
        """Convert BGP message type number to string"""
        types = {
            1: 'OPEN',
            2: 'UPDATE',
            3: 'NOTIFICATION',
            4: 'KEEPALIVE'
        }
        return types.get(msg_type, f'UNKNOWN({msg_type})')

    def packet_handler(self, packet):
        """Handle captured packets"""
        global traffic_stats, packet_logs, real_time_data, bgp_routes

        if not self.running:
            return

        traffic_stats['total_packets'] += 1

        # Check if it's a BGP packet
        is_bgp = packet.haslayer(TCP) and (packet[TCP].sport == 179 or packet[TCP].dport == 179)
        is_encrypted = False
        is_forwarded = False

        if is_bgp:
            traffic_stats['bgp_packets'] += 1
            bgp_info = self.parse_bgp_packet(packet)
            if bgp_info:
                # Update BGP routes (simplified)
                route_key = f"{bgp_info['src']}->{bgp_info['dst']}"
                bgp_routes[route_key] = bgp_info

        if packet.haslayer(TCP):
            payload = bytes(packet[TCP].payload)
            if len(payload) > 0:
                # Simple heuristic: check for high randomness (encrypted data)
                if len(set(payload)) > len(payload) * 0.7:
                    is_encrypted = True
                    traffic_stats['encrypted_packets'] += 1

        if packet.haslayer(IP):
            if packet[IP].ttl < 64:  # Likely forwarded
                is_forwarded = True
                traffic_stats['forwarded_packets'] += 1

        # Create packet log entry
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'src': packet[IP].src if packet.haslayer(IP) else 'N/A',
            'dst': packet[IP].dst if packet.haslayer(IP) else 'N/A',
            'protocol': packet.name,
            'size': len(packet),
            'is_bgp': is_bgp,
            'is_encrypted': is_encrypted,
            'is_forwarded': is_forwarded,
            'port': packet[TCP].sport if packet.haslayer(TCP) else 'N/A'
        }

        packet_logs.append(log_entry)

        current_time = datetime.now()
        real_time_data.append({
            'timestamp': current_time.isoformat(),
            'total': traffic_stats['total_packets'],
            'bgp': traffic_stats['bgp_packets'],
            'encrypted': traffic_stats['encrypted_packets'],
            'forwarded': traffic_stats['forwarded_packets']
        })

        socketio.emit('packet_update', {
            'stats': traffic_stats,
            'latest_packet': log_entry,
            'chart_data': list(real_time_data)[-10:]  # Last 10 data points
        })

    def start_sniffing(self, interface='any'):
        """Start packet sniffing"""
        self.running = True
        self.interface = interface
        logger.info(f"Starting BGP sniffer on interface: {interface}")

        try:
            scapy.sniff(
                iface=interface if interface != 'any' else None,
                prn=self.packet_handler,
                stop_filter=lambda x: not self.running,
                store=False
            )
        except Exception as e:
            logger.error(f"Error during sniffing: {e}")
            self.running = False

    def stop_sniffing(self):
        """Stop packet sniffing"""
        self.running = False
        logger.info("BGP sniffer stopped")

#  sniffer
bgp_sniffer = BGPSniffer()

# API Routes
@app.route('/')
def index():
    """Serve main dashboard"""
    return render_template('dashboard.html')

@app.route('/api/status')
def get_status():
    """Get sniffer status"""
    return jsonify({
        'active': sniffer_active,
        'interface': bgp_sniffer.interface,
        'stats': traffic_stats
    })

@app.route('/api/start', methods=['POST'])
def start_sniffer():
    """Start the BGP sniffer"""
    global sniffer_active, sniffer_thread

    if sniffer_active:
        return jsonify({'error': 'Sniffer already running'}), 400

    interface = request.json.get('interface', 'any')

    def sniffer_worker():
        bgp_sniffer.start_sniffing(interface)

    sniffer_thread = threading.Thread(target=sniffer_worker)
    sniffer_thread.daemon = True
    sniffer_thread.start()

    sniffer_active = True

    return jsonify({
        'message': 'BGP sniffer started',
        'interface': interface
    })

@app.route('/api/stop', methods=['POST'])
def stop_sniffer():
    """Stop the BGP sniffer"""
    global sniffer_active

    if not sniffer_active:
        return jsonify({'error': 'Sniffer not running'}), 400

    bgp_sniffer.stop_sniffing()
    sniffer_active = False

    return jsonify({'message': 'BGP sniffer stopped'})

@app.route('/api/routes')
def get_routes():
    """Get active BGP routes"""
    return jsonify({
        'routes': list(bgp_routes.values()),
        'count': len(bgp_routes)
    })

@app.route('/api/traffic')
def get_traffic():
    """Get traffic statistics"""
    return jsonify({
        'stats': traffic_stats,
        'chart_data': list(real_time_data)
    })

@app.route('/api/logs')
def get_logs():
    """Get packet logs"""
    limit = request.args.get('limit', 100, type=int)
    filter_type = request.args.get('filter', 'all')

    logs = list(packet_logs)

    # Apply filters
    if filter_type == 'bgp':
        logs = [log for log in logs if log['is_bgp']]
    elif filter_type == 'encrypted':
        logs = [log for log in logs if log['is_encrypted']]
    elif filter_type == 'forwarded':
        logs = [log for log in logs if log['is_forwarded']]

    # Limit results
    logs = logs[-limit:]

    return jsonify({
        'logs': logs,
        'total': len(packet_logs),
        'filtered': len(logs)
    })

@app.route('/api/interfaces')
def get_interfaces():
    """Get available network interfaces"""
    try:
        interfaces = scapy.get_if_list()
        return jsonify({'interfaces': interfaces})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/clear-logs', methods=['POST'])
def clear_logs():
    """Clear packet logs"""
    global packet_logs, real_time_data
    packet_logs.clear()
    real_time_data.clear()
    return jsonify({'message': 'Logs cleared'})

@app.route('/api/reset-stats', methods=['POST'])
def reset_stats():
    """Reset traffic statistics"""
    global traffic_stats
    traffic_stats = {
        'total_packets': 0,
        'bgp_packets': 0,
        'encrypted_packets': 0,
        'forwarded_packets': 0
    }
    return jsonify({'message': 'Statistics reset'})


@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    emit('status', {
        'active': sniffer_active,
        'stats': traffic_stats
    })

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info('Client disconnected')

# Demo
def generate_demo_data():
    """Generate demo data for testing when no real traffic is available"""
    while True:
        if sniffer_active:

            demo_packet = {
                'timestamp': datetime.now().isoformat(),
                'src': f"192.168.1.{random.randint(1, 100)}",
                'dst': f"10.0.0.{random.randint(1, 100)}",
                'protocol': random.choice(['TCP', 'UDP', 'ICMP']),
                'size': random.randint(64, 1500),
                'is_bgp': random.random() < 0.1,  # 10% BGP
                'is_encrypted': random.random() < 0.3,  # 30% encrypted
                'is_forwarded': random.random() < 0.2,  # 20% forwarded
                'port': random.choice([179, 80, 443, 22, 53])
            }


            traffic_stats['total_packets'] += 1
            if demo_packet['is_bgp']:
                traffic_stats['bgp_packets'] += 1
            if demo_packet['is_encrypted']:
                traffic_stats['encrypted_packets'] += 1
            if demo_packet['is_forwarded']:
                traffic_stats['forwarded_packets'] += 1

            packet_logs.append(demo_packet)


            real_time_data.append({
                'timestamp': datetime.now().isoformat(),
                'total': traffic_stats['total_packets'],
                'bgp': traffic_stats['bgp_packets'],
                'encrypted': traffic_stats['encrypted_packets'],
                'forwarded': traffic_stats['forwarded_packets']
            })


            socketio.emit('packet_update', {
                'stats': traffic_stats,
                'latest_packet': demo_packet,
                'chart_data': list(real_time_data)[-10:]
            })

        time.sleep(0.5)

if __name__ == '__main__':
    # Start demo data generator in background for testing
    demo_thread = threading.Thread(target=generate_demo_data)
    demo_thread.daemon = True
    # demo_thread.start()  # Uncomment for demo mode

    # Run the Flask app
    socketio.run(app, debug=True, host='0.0.0.0', port=8080)