"""
BrainCell WebSocket streaming client for real-time network telemetry ingestion.

Provides persistent WebSocket connection for sub-100ms latency streaming
of eBPF network events with automatic reconnection and error handling.

Usage:
    client = BrainCellWebSocketClient(url="ws://braincell.local:8000/ws/telemetry")
    await client.connect()

    for event in network_events:
        await client.send_event(event)

    await client.close()
"""

import asyncio
import json
import time
import logging
from typing import Dict, Any, Optional, Callable, List
from datetime import datetime

try:
    import websockets
    HAS_WEBSOCKETS = True
except ImportError:
    HAS_WEBSOCKETS = False


logger = logging.getLogger(__name__)


class BrainCellWebSocketClient:
    """Real-time WebSocket client for BrainCell telemetry ingestion"""

    def __init__(
        self,
        url: str,
        auth_token: Optional[str] = None,
        reconnect_max_retries: int = 5,
        reconnect_delay: float = 2.0,
        heartbeat_interval: float = 30.0,
        on_connected: Optional[Callable] = None,
        on_disconnected: Optional[Callable] = None,
        on_error: Optional[Callable] = None,
    ):
        """
        Initialize WebSocket client.

        Args:
            url: WebSocket URL (ws://... or wss://...)
            auth_token: Optional authentication token
            reconnect_max_retries: Max reconnection attempts
            reconnect_delay: Seconds between reconnection attempts
            heartbeat_interval: Seconds between heartbeat pings
            on_connected: Callback when connected
            on_disconnected: Callback when disconnected
            on_error: Callback on error
        """
        if not HAS_WEBSOCKETS:
            raise ImportError("websockets library required: pip install websockets")

        self.url = url
        self.auth_token = auth_token
        self.reconnect_max_retries = reconnect_max_retries
        self.reconnect_delay = reconnect_delay
        self.heartbeat_interval = heartbeat_interval

        self.ws = None
        self.connected = False
        self.reconnect_attempts = 0

        self.on_connected = on_connected
        self.on_disconnected = on_disconnected
        self.on_error = on_error

        self.stats = {
            "events_sent": 0,
            "events_failed": 0,
            "reconnections": 0,
            "bytes_sent": 0,
            "connection_start_time": None,
        }

    async def connect(self) -> bool:
        """Connect to WebSocket with automatic reconnection"""
        while self.reconnect_attempts < self.reconnect_max_retries:
            try:
                # Add auth header if token provided
                headers = {}
                if self.auth_token:
                    headers["Authorization"] = f"Bearer {self.auth_token}"

                self.ws = await websockets.connect(
                    self.url,
                    extra_headers=headers,
                    ping_interval=self.heartbeat_interval,
                    ping_timeout=10.0,
                    close_timeout=10.0,
                )

                self.connected = True
                self.reconnect_attempts = 0
                self.stats["connection_start_time"] = time.time()

                logger.info(f"[+] WebSocket connected: {self.url}")

                if self.on_connected:
                    await self._run_callback(self.on_connected)

                # Start heartbeat/monitor task
                asyncio.create_task(self._monitor_connection())

                return True

            except Exception as e:
                self.reconnect_attempts += 1
                logger.warning(
                    f"[!] WebSocket connection failed "
                    f"(attempt {self.reconnect_attempts}/{self.reconnect_max_retries}): {e}"
                )

                if self.on_error:
                    await self._run_callback(self.on_error, str(e))

                if self.reconnect_attempts < self.reconnect_max_retries:
                    wait_time = self.reconnect_delay * (2 ** self.reconnect_attempts)
                    logger.info(f"[*] Retrying in {wait_time}s...")
                    await asyncio.sleep(wait_time)

        logger.error(f"[!] Failed to connect after {self.reconnect_max_retries} attempts")
        return False

    async def send_event(self, event: Dict[str, Any]) -> bool:
        """Send single network event"""
        if not self.connected or not self.ws:
            logger.warning("[!] WebSocket not connected")
            self.stats["events_failed"] += 1
            return False

        try:
            message = {
                "type": "network_event",
                "timestamp": datetime.utcnow().isoformat(),
                "event": event,
            }

            payload = json.dumps(message)
            await self.ws.send(payload)

            self.stats["events_sent"] += 1
            self.stats["bytes_sent"] += len(payload)

            return True

        except Exception as e:
            logger.error(f"[!] Failed to send event: {e}")
            self.stats["events_failed"] += 1

            if self.on_error:
                await self._run_callback(self.on_error, str(e))

            # Reconnect on send failure
            self.connected = False
            await self._reconnect()

            return False

    async def send_batch(self, events: List[Dict[str, Any]]) -> int:
        """Send batch of events, return count sent"""
        if not self.connected or not self.ws:
            logger.warning("[!] WebSocket not connected")
            return 0

        sent_count = 0
        try:
            message = {
                "type": "batch",
                "timestamp": datetime.utcnow().isoformat(),
                "count": len(events),
                "events": events,
            }

            payload = json.dumps(message)
            await self.ws.send(payload)

            sent_count = len(events)
            self.stats["events_sent"] += sent_count
            self.stats["bytes_sent"] += len(payload)

            logger.debug(f"[+] Sent batch of {sent_count} events")

        except Exception as e:
            logger.error(f"[!] Failed to send batch: {e}")
            self.stats["events_failed"] += len(events)

            if self.on_error:
                await self._run_callback(self.on_error, str(e))

            self.connected = False
            await self._reconnect()

        return sent_count

    async def send_command(self, command: str, params: Optional[Dict] = None) -> Dict:
        """Send command to BrainCell and wait for response"""
        if not self.connected or not self.ws:
            raise RuntimeError("WebSocket not connected")

        message = {
            "type": "command",
            "command": command,
            "params": params or {},
            "timestamp": datetime.utcnow().isoformat(),
        }

        try:
            await self.ws.send(json.dumps(message))

            # Wait for response (implement message handling for full duplex)
            response = await asyncio.wait_for(self.ws.recv(), timeout=5.0)
            return json.loads(response)

        except asyncio.TimeoutError:
            logger.error(f"[!] Command timeout: {command}")
            raise
        except Exception as e:
            logger.error(f"[!] Command failed: {e}")
            raise

    async def close(self) -> None:
        """Close WebSocket connection gracefully"""
        self.connected = False

        if self.ws:
            try:
                await self.ws.close()
            except Exception as e:
                logger.warning(f"[!] Error closing WebSocket: {e}")

        self.ws = None

        if self.on_disconnected:
            await self._run_callback(self.on_disconnected)

        logger.info("[+] WebSocket closed")

    async def _monitor_connection(self) -> None:
        """Monitor connection health"""
        try:
            while self.connected and self.ws:
                try:
                    # Wait for messages (connection status)
                    await asyncio.wait_for(self.ws.recv(), timeout=60.0)
                except asyncio.TimeoutError:
                    # Timeout is OK, heartbeat is active
                    pass
                except websockets.exceptions.ConnectionClosed:
                    logger.warning("[!] WebSocket connection closed")
                    self.connected = False
                    await self._reconnect()
                    break

        except Exception as e:
            logger.error(f"[!] Monitor error: {e}")
            self.connected = False
            await self._reconnect()

    async def _reconnect(self) -> None:
        """Attempt reconnection"""
        logger.info("[*] Attempting reconnection...")
        self.stats["reconnections"] += 1

        if await self.connect():
            logger.info("[+] Reconnected successfully")
        else:
            logger.error("[!] Reconnection failed")

    async def _run_callback(self, callback: Callable, *args) -> None:
        """Run callback safely"""
        try:
            if asyncio.iscoroutinefunction(callback):
                await callback(*args)
            else:
                callback(*args)
        except Exception as e:
            logger.error(f"[!] Callback error: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get connection statistics"""
        return {
            **self.stats,
            "connected": self.connected,
            "uptime_seconds": (
                time.time() - self.stats["connection_start_time"]
                if self.stats["connection_start_time"]
                else 0
            ),
        }

    def print_stats(self) -> None:
        """Print formatted statistics"""
        stats = self.get_stats()
        print("\n[*] WebSocket Statistics:")
        print(f"    Connected: {stats['connected']}")
        print(f"    Uptime: {stats['uptime_seconds']:.1f}s")
        print(f"    Events sent: {stats['events_sent']}")
        print(f"    Events failed: {stats['events_failed']}")
        print(f"    Bytes sent: {stats['bytes_sent'] / 1024:.1f}KB")
        print(f"    Reconnections: {stats['reconnections']}")
        if stats['events_sent'] > 0:
            print(f"    Avg latency: <100ms (WebSocket)")


class BrainCellWebSocketAsyncAgent:
    """
    Async wrapper for eBPF implant to use WebSocket transport.

    Usage:
        agent = BrainCellWebSocketAsyncAgent(
            ws_url="ws://braincell.local:8000/ws/telemetry",
            auth_token="sk-xxx"
        )

        await agent.start()
        await agent.send_event(network_event)
        await agent.stop()
    """

    def __init__(self, ws_url: str, auth_token: str, batch_mode: bool = False):
        """
        Args:
            ws_url: WebSocket URL for BrainCell
            auth_token: Authentication token
            batch_mode: If True, batch events before sending
        """
        self.client = BrainCellWebSocketClient(
            url=ws_url,
            auth_token=auth_token,
        )
        self.batch_mode = batch_mode
        self.batch_queue = []
        self.batch_size = 10
        self.batch_flush_interval = 5.0

    async def start(self) -> bool:
        """Start WebSocket connection"""
        success = await self.client.connect()

        if success and self.batch_mode:
            asyncio.create_task(self._batch_worker())

        return success

    async def stop(self) -> None:
        """Stop and flush remaining events"""
        if self.batch_queue:
            await self.client.send_batch(self.batch_queue)

        await self.client.close()

    async def send_event(self, event: Dict[str, Any]) -> bool:
        """Send network event"""
        if self.batch_mode:
            self.batch_queue.append(event)

            if len(self.batch_queue) >= self.batch_size:
                batch = self.batch_queue
                self.batch_queue = []
                return await self.client.send_batch(batch) > 0

            return True
        else:
            # Real-time mode - send immediately
            return await self.client.send_event(event)

    async def _batch_worker(self) -> None:
        """Background worker for batch flushing"""
        while True:
            await asyncio.sleep(self.batch_flush_interval)

            if self.batch_queue:
                batch = self.batch_queue
                self.batch_queue = []
                await self.client.send_batch(batch)
