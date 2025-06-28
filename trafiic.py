import json
import sqlite3
import logging
import time
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, asdict
from pathlib import Path
import threading
from contextlib import contextmanager
import csv
import os

@dataclass
class TransferMetrics:
    """Data class to hold transfer metrics."""
    transfer_id: str
    timestamp: float
    operation_type: str  # 'send' or 'receive'
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    bytes_sent: int
    bytes_received: int
    duration_ms: float
    status: str  # 'success', 'failed', 'timeout', 'retry'
    error_message: Optional[str] = None
    retry_count: int = 0
    data_type: Optional[str] = None
    encryption_method: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class TransferLogger:
    """
    Comprehensive logging system for data transfer operations.
    Supports both file-based and database logging with real-time monitoring.
    """

    def __init__(self, log_dir: str = "./transfer_logs", db_path: str = None,
                 enable_file_logging: bool = True, enable_database: bool = True):
        """
        Initialize the transfer logger.

        Args:
            log_dir: Directory for log files
            db_path: SQLite database path (None for default)
            enable_file_logging: Enable file-based logging
            enable_database: Enable database logging
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)

        self.enable_file_logging = enable_file_logging
        self.enable_database = enable_database

        # Database setup
        if enable_database:
            self.db_path = db_path or str(self.log_dir / "transfer_metrics.db")
            self._init_database()

        # File logging setup
        if enable_file_logging:
            self._setup_file_logging()

        # Thread lock for concurrent operations
        self._lock = threading.Lock()

        # In-memory statistics
        self.session_stats = {
            'total_transfers': 0,
            'successful_transfers': 0,
            'failed_transfers': 0,
            'total_bytes_sent': 0,
            'total_bytes_received': 0,
            'session_start': time.time()
        }

    def _setup_file_logging(self):
        """Setup file-based logging configurations."""
        # Main transfer log
        self.transfer_log_file = self.log_dir / f"transfers_{datetime.now().strftime('%Y%m%d')}.log"

        # CSV metrics file
        self.csv_log_file = self.log_dir / f"metrics_{datetime.now().strftime('%Y%m%d')}.csv"

        # Setup structured logging
        self.logger = logging.getLogger('transfer_logger')
        self.logger.setLevel(logging.INFO)

        # Create file handler if not exists
        if not self.logger.handlers:
            handler = logging.FileHandler(self.transfer_log_file)
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def _init_database(self):
        """Initialize SQLite database and create tables."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS transfer_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    transfer_id TEXT UNIQUE NOT NULL,
                    timestamp REAL NOT NULL,
                    operation_type TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    source_port INTEGER NOT NULL,
                    destination_ip TEXT NOT NULL,
                    destination_port INTEGER NOT NULL,
                    bytes_sent INTEGER NOT NULL,
                    bytes_received INTEGER NOT NULL,
                    duration_ms REAL NOT NULL,
                    status TEXT NOT NULL,
                    error_message TEXT,
                    retry_count INTEGER DEFAULT 0,
                    data_type TEXT,
                    encryption_method TEXT,
                    metadata TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Create indexes for better query performance
            conn.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON transfer_metrics(timestamp)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_status ON transfer_metrics(status)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_destination ON transfer_metrics(destination_ip, destination_port)')

    @contextmanager
    def _get_db_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Enable dict-like access
        try:
            yield conn
        finally:
            conn.close()

    def log_transfer(self, metrics: TransferMetrics):
        """
        Log transfer metrics to configured destinations.

        Args:
            metrics: TransferMetrics object containing transfer data
        """
        with self._lock:
            # Update session statistics
            self.session_stats['total_transfers'] += 1
            if metrics.status == 'success':
                self.session_stats['successful_transfers'] += 1
            else:
                self.session_stats['failed_transfers'] += 1

            self.session_stats['total_bytes_sent'] += metrics.bytes_sent
            self.session_stats['total_bytes_received'] += metrics.bytes_received

            # Database logging
            if self.enable_database:
                self._log_to_database(metrics)

            # File logging
            if self.enable_file_logging:
                self._log_to_file(metrics)
                self._log_to_csv(metrics)

    def _log_to_database(self, metrics: TransferMetrics):
        """Log metrics to SQLite database."""
        try:
            with self._get_db_connection() as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO transfer_metrics (
                        transfer_id, timestamp, operation_type, source_ip, source_port,
                        destination_ip, destination_port, bytes_sent, bytes_received,
                        duration_ms, status, error_message, retry_count, data_type,
                        encryption_method, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    metrics.transfer_id, metrics.timestamp, metrics.operation_type,
                    metrics.source_ip, metrics.source_port, metrics.destination_ip,
                    metrics.destination_port, metrics.bytes_sent, metrics.bytes_received,
                    metrics.duration_ms, metrics.status, metrics.error_message,
                    metrics.retry_count, metrics.data_type, metrics.encryption_method,
                    json.dumps(metrics.metadata) if metrics.metadata else None
                ))
                conn.commit()
        except Exception as e:
            print(f"Database logging error: {e}")

    def _log_to_file(self, metrics: TransferMetrics):
        """Log metrics to structured log file."""
        try:
            log_entry = {
                'transfer_id': metrics.transfer_id,
                'timestamp': datetime.fromtimestamp(metrics.timestamp, timezone.utc).isoformat(),
                'operation': metrics.operation_type,
                'source': f"{metrics.source_ip}:{metrics.source_port}",
                'destination': f"{metrics.destination_ip}:{metrics.destination_port}",
                'bytes_sent': metrics.bytes_sent,
                'bytes_received': metrics.bytes_received,
                'duration_ms': metrics.duration_ms,
                'status': metrics.status,
                'retry_count': metrics.retry_count
            }

            if metrics.error_message:
                log_entry['error'] = metrics.error_message

            self.logger.info(json.dumps(log_entry))
        except Exception as e:
            print(f"File logging error: {e}")

    def _log_to_csv(self, metrics: TransferMetrics):
        """Log metrics to CSV file for easy analysis."""
        try:
            # Check if CSV file exists and write header if needed
            write_header = not self.csv_log_file.exists()

            with open(self.csv_log_file, 'a', newline='') as csvfile:
                fieldnames = [
                    'transfer_id', 'timestamp', 'datetime', 'operation_type',
                    'source_ip', 'source_port', 'destination_ip', 'destination_port',
                    'bytes_sent', 'bytes_received', 'duration_ms', 'status',
                    'error_message', 'retry_count', 'data_type', 'encryption_method'
                ]

                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

                if write_header:
                    writer.writeheader()

                row_data = asdict(metrics)
                row_data['datetime'] = datetime.fromtimestamp(metrics.timestamp).isoformat()
                row_data['metadata'] = json.dumps(metrics.metadata) if metrics.metadata else ''

                writer.writerow(row_data)
        except Exception as e:
            print(f"CSV logging error: {e}")

    def get_transfer_stats(self, hours: int = 24) -> Dict[str, Any]:
        """
        Get transfer statistics for the specified time period.

        Args:
            hours: Number of hours to look back

        Returns:
            Dictionary containing transfer statistics
        """
        if not self.enable_database:
            return self.session_stats

        cutoff_time = time.time() - (hours * 3600)

        try:
            with self._get_db_connection() as conn:
                # Basic stats
                stats = conn.execute('''
                    SELECT 
                        COUNT(*) as total_transfers,
                        SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as successful_transfers,
                        SUM(CASE WHEN status != 'success' THEN 1 ELSE 0 END) as failed_transfers,
                        SUM(bytes_sent) as total_bytes_sent,
                        SUM(bytes_received) as total_bytes_received,
                        AVG(duration_ms) as avg_duration_ms,
                        MIN(timestamp) as earliest_transfer,
                        MAX(timestamp) as latest_transfer
                    FROM transfer_metrics 
                    WHERE timestamp > ?
                ''', (cutoff_time,)).fetchone()

                # Top destinations
                destinations = conn.execute('''
                    SELECT destination_ip, destination_port, COUNT(*) as transfer_count,
                           SUM(bytes_sent) as total_bytes
                    FROM transfer_metrics 
                    WHERE timestamp > ?
                    GROUP BY destination_ip, destination_port
                    ORDER BY transfer_count DESC
                    LIMIT 10
                ''', (cutoff_time,)).fetchall()

                # Error summary
                errors = conn.execute('''
                    SELECT error_message, COUNT(*) as error_count
                    FROM transfer_metrics 
                    WHERE timestamp > ? AND status != 'success' AND error_message IS NOT NULL
                    GROUP BY error_message
                    ORDER BY error_count DESC
                    LIMIT 5
                ''', (cutoff_time,)).fetchall()

                return {
                    'time_period_hours': hours,
                    'total_transfers': stats['total_transfers'] or 0,
                    'successful_transfers': stats['successful_transfers'] or 0,
                    'failed_transfers': stats['failed_transfers'] or 0,
                    'success_rate': (stats['successful_transfers'] or 0) / max(stats['total_transfers'] or 1, 1) * 100,
                    'total_bytes_sent': stats['total_bytes_sent'] or 0,
                    'total_bytes_received': stats['total_bytes_received'] or 0,
                    'avg_duration_ms': round(stats['avg_duration_ms'] or 0, 2),
                    'earliest_transfer': stats['earliest_transfer'],
                    'latest_transfer': stats['latest_transfer'],
                    'top_destinations': [dict(row) for row in destinations],
                    'common_errors': [dict(row) for row in errors]
                }
        except Exception as e:
            print(f"Error getting stats: {e}")
            return self.session_stats

    def get_recent_transfers(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get recent transfer records.

        Args:
            limit: Maximum number of records to return

        Returns:
            List of transfer records
        """
        if not self.enable_database:
            return []

        try:
            with self._get_db_connection() as conn:
                records = conn.execute('''
                    SELECT * FROM transfer_metrics 
                    ORDER BY timestamp DESC 
                    LIMIT ?
                ''', (limit,)).fetchall()

                return [dict(row) for row in records]
        except Exception as e:
            print(f"Error getting recent transfers: {e}")
            return []

    def generate_report(self, output_file: str = None, hours: int = 24) -> str:
        """
        Generate a comprehensive transfer report.

        Args:
            output_file: Output file path (None for string return)
            hours: Hours to include in report

        Returns:
            Report content as string
        """
        stats = self.get_transfer_stats(hours)

        report_lines = [
            f"=== Data Transfer Report ===",
            f"Report generated: {datetime.now().isoformat()}",
            f"Time period: Last {hours} hours",
            f"",
            f"=== Summary Statistics ===",
            f"Total transfers: {stats['total_transfers']:,}",
            f"Successful transfers: {stats['successful_transfers']:,}",
            f"Failed transfers: {stats['failed_transfers']:,}",
            f"Success rate: {stats['success_rate']:.1f}%",
            f"Total bytes sent: {stats['total_bytes_sent']:,}",
            f"Total bytes received: {stats['total_bytes_received']:,}",
            f"Average duration: {stats['avg_duration_ms']:.1f}ms",
            f"",
            f"=== Top Destinations ===",
        ]

        for dest in stats['top_destinations'][:5]:
            report_lines.append(f"  {dest['destination_ip']}:{dest['destination_port']} - "
                                f"{dest['transfer_count']} transfers, {dest['total_bytes']:,} bytes")

        if stats['common_errors']:
            report_lines.extend([
                f"",
                f"=== Common Errors ===",
            ])
            for error in stats['common_errors']:
                report_lines.append(f"  {error['error_message']} ({error['error_count']} times)")

        report_content = "\n".join(report_lines)

        if output_file:
            with open(output_file, 'w') as f:
                f.write(report_content)

        return report_content

# Enhanced TCP Forwarder with integrated logging
class LoggingTCPForwarder:
    """TCP Forwarder with integrated transfer logging."""

    def __init__(self, logger: TransferLogger, timeout: int = 30):
        self.logger = logger
        self.timeout = timeout

    def forward_with_logging(self, host: str, port: int, data: bytes,
                             data_type: str = None, encryption_method: str = None,
                             metadata: Dict[str, Any] = None) -> bool:
        """
        Forward data with comprehensive logging.

        Args:
            host: Destination host
            port: Destination port
            data: Data to send
            data_type: Type of data being sent
            encryption_method: Encryption method used
            metadata: Additional metadata

        Returns:
            True if successful, False otherwise
        """
        import socket
        import uuid

        transfer_id = str(uuid.uuid4())
        start_time = time.time()

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect((host, port))

                # Get local address
                local_ip, local_port = sock.getsockname()

                # Send data
                sock.sendall(data)

                # Calculate metrics
                end_time = time.time()
                duration_ms = (end_time - start_time) * 1000

                # Log successful transfer
                metrics = TransferMetrics(
                    transfer_id=transfer_id,
                    timestamp=start_time,
                    operation_type='send',
                    source_ip=local_ip,
                    source_port=local_port,
                    destination_ip=host,
                    destination_port=port,
                    bytes_sent=len(data),
                    bytes_received=0,
                    duration_ms=duration_ms,
                    status='success',
                    data_type=data_type,
                    encryption_method=encryption_method,
                    metadata=metadata
                )

                self.logger.log_transfer(metrics)
                return True

        except Exception as e:
            # Log failed transfer
            end_time = time.time()
            duration_ms = (end_time - start_time) * 1000

            metrics = TransferMetrics(
                transfer_id=transfer_id,
                timestamp=start_time,
                operation_type='send',
                source_ip='unknown',
                source_port=0,
                destination_ip=host,
                destination_port=port,
                bytes_sent=0,
                bytes_received=0,
                duration_ms=duration_ms,
                status='failed',
                error_message=str(e),
                data_type=data_type,
                encryption_method=encryption_method,
                metadata=metadata
            )

            self.logger.log_transfer(metrics)
            return False

# Demonstration and example usage
def demonstrate_transfer_logging():
    """Demonstrate the transfer logging system."""

    print("=== Transfer Logging Demonstration ===\n")

    # Initialize logger
    logger = TransferLogger(
        log_dir="./demo_logs",
        enable_file_logging=True,
        enable_database=True
    )

    # Simulate some transfers
    import uuid
    current_time = time.time()

    # Successful transfer
    success_metrics = TransferMetrics(
        transfer_id=str(uuid.uuid4()),
        timestamp=current_time,
        operation_type='send',
        source_ip='192.168.1.10',
        source_port=12345,
        destination_ip='10.0.0.5',
        destination_port=8888,
        bytes_sent=1024,
        bytes_received=0,
        duration_ms=45.2,
        status='success',
        data_type='encrypted_prefixes',
        encryption_method='AES-128-CBC',
        metadata={'priority': 'high', 'source_router': 'R1'}
    )

    # Failed transfer
    failed_metrics = TransferMetrics(
        transfer_id=str(uuid.uuid4()),
        timestamp=current_time - 300,
        operation_type='send',
        source_ip='192.168.1.10',
        source_port=12346,
        destination_ip='10.0.0.6',
        destination_port=8888,
        bytes_sent=0,
        bytes_received=0,
        duration_ms=30000.0,
        status='timeout',
        error_message='Connection timeout after 30 seconds',
        retry_count=2,
        data_type='encrypted_prefixes',
        encryption_method='AES-128-CBC'
    )

    # Log the transfers
    logger.log_transfer(success_metrics)
    logger.log_transfer(failed_metrics)

    print("✓ Logged sample transfers")

    # Get statistics
    stats = logger.get_transfer_stats(hours=1)
    print(f"\n=== Transfer Statistics ===")
    print(f"Total transfers: {stats['total_transfers']}")
    print(f"Success rate: {stats['success_rate']:.1f}%")
    print(f"Total bytes sent: {stats['total_bytes_sent']:,}")

    # Generate report
    report = logger.generate_report(hours=24)
    print(f"\n=== Sample Report ===")
    print(report[:500] + "..." if len(report) > 500 else report)

    return logger

if __name__ == "__main__":
    demonstrate_transfer_logging()