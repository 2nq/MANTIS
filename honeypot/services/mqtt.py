"""MQTT broker honeypot — captures CONNECT credentials, SUBSCRIBE topics, PUBLISH payloads."""

import asyncio
import struct
from ..models import EventType
from . import BaseHoneypotService

# MQTT packet types (high nibble of byte 0)
CONNECT = 1
CONNACK = 2
PUBLISH = 3
PUBACK = 4
SUBSCRIBE = 8
SUBACK = 9
UNSUBSCRIBE = 10
UNSUBACK = 11
PINGREQ = 12
PINGRESP = 13
DISCONNECT = 14


def _decode_remaining_length(data: bytes, offset: int) -> tuple[int, int]:
    """Decode MQTT variable-length encoding. Returns (value, bytes_consumed)."""
    multiplier = 1
    value = 0
    idx = offset
    while idx < len(data):
        encoded = data[idx]
        value += (encoded & 0x7F) * multiplier
        idx += 1
        if (encoded & 0x80) == 0:
            return value, idx - offset
        multiplier *= 128
        if multiplier > 128 * 128 * 128:
            break
    return value, idx - offset


def _decode_utf8_string(data: bytes, offset: int) -> tuple[str, int]:
    """Decode MQTT UTF-8 prefixed string. Returns (string, bytes_consumed)."""
    if offset + 2 > len(data):
        return "", 0
    str_len = struct.unpack("!H", data[offset:offset + 2])[0]
    if offset + 2 + str_len > len(data):
        return data[offset + 2:].decode("utf-8", errors="replace"), len(data) - offset
    s = data[offset + 2:offset + 2 + str_len].decode("utf-8", errors="replace")
    return s, 2 + str_len


def _build_connack(return_code: int = 0) -> bytes:
    """Build CONNACK packet (connection accepted)."""
    return bytes([CONNACK << 4, 2, 0, return_code])


def _build_suback(packet_id: int, granted_qos: list[int]) -> bytes:
    """Build SUBACK packet."""
    payload = struct.pack("!H", packet_id) + bytes(granted_qos)
    remaining = len(payload)
    return bytes([SUBACK << 4, remaining]) + payload


def _build_puback(packet_id: int) -> bytes:
    """Build PUBACK packet."""
    return bytes([PUBACK << 4, 2]) + struct.pack("!H", packet_id)


def _build_pingresp() -> bytes:
    return bytes([PINGRESP << 4, 0])


def _build_unsuback(packet_id: int) -> bytes:
    return bytes([UNSUBACK << 4, 2]) + struct.pack("!H", packet_id)


class MQTTHoneypot(BaseHoneypotService):
    service_name = "mqtt"

    async def start(self):
        port = self.config.port
        self._server = await asyncio.start_server(
            self._handle_client, "0.0.0.0", port,
        )
        self.logger.info("MQTT honeypot listening on port %d", port)

    async def stop(self):
        if hasattr(self, "_server") and self._server:
            self._server.close()
            await self._server.wait_closed()
        self.logger.info("MQTT service stopped")

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        if not addr:
            writer.close()
            return
        src_ip, src_port = addr[0], addr[1]
        session = await self._create_session(src_ip, src_port, self.config.port)

        try:
            while True:
                # Read fixed header (at least 2 bytes)
                try:
                    first_byte = await asyncio.wait_for(reader.readexactly(1), timeout=60)
                except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                    break

                packet_type = (first_byte[0] >> 4) & 0x0F
                flags = first_byte[0] & 0x0F

                # Decode remaining length (variable-length encoding)
                remaining_length = 0
                multiplier = 1
                for _ in range(4):
                    try:
                        b = await asyncio.wait_for(reader.readexactly(1), timeout=5)
                    except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                        remaining_length = -1
                        break
                    remaining_length += (b[0] & 0x7F) * multiplier
                    if (b[0] & 0x80) == 0:
                        break
                    multiplier *= 128

                if remaining_length < 0:
                    break
                if remaining_length > 262144:  # 256KB max
                    await self._log(session, EventType.REQUEST, {
                        "warning": "oversized_packet",
                        "packet_type": packet_type,
                        "remaining_length": remaining_length,
                    })
                    break

                # Read payload
                payload = b""
                if remaining_length > 0:
                    try:
                        payload = await asyncio.wait_for(reader.readexactly(remaining_length), timeout=10)
                    except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                        break

                if packet_type == CONNECT:
                    await self._handle_connect(session, payload, writer)
                elif packet_type == PUBLISH:
                    await self._handle_publish(session, payload, flags, writer)
                elif packet_type == SUBSCRIBE:
                    await self._handle_subscribe(session, payload, writer)
                elif packet_type == UNSUBSCRIBE:
                    await self._handle_unsubscribe(session, payload, writer)
                elif packet_type == PINGREQ:
                    writer.write(_build_pingresp())
                    await writer.drain()
                elif packet_type == DISCONNECT:
                    break
                else:
                    await self._log(session, EventType.REQUEST, {
                        "unknown_packet_type": packet_type,
                        "payload_len": remaining_length,
                    })

        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            pass
        except Exception as e:
            self.logger.debug("MQTT session error: %s", e)
        finally:
            await self._end_session(session)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_connect(self, session, payload: bytes, writer):
        """Parse CONNECT packet — extract client ID, username, password."""
        offset = 0

        # Protocol name
        proto_name, consumed = _decode_utf8_string(payload, offset)
        offset += consumed

        if offset >= len(payload):
            writer.write(_build_connack(0))
            await writer.drain()
            return

        # Protocol level
        proto_level = payload[offset] if offset < len(payload) else 0
        offset += 1

        # Connect flags
        connect_flags = payload[offset] if offset < len(payload) else 0
        offset += 1
        has_username = bool(connect_flags & 0x80)
        has_password = bool(connect_flags & 0x40)
        will_retain = bool(connect_flags & 0x20)
        will_qos = (connect_flags >> 3) & 0x03
        has_will = bool(connect_flags & 0x04)
        clean_session = bool(connect_flags & 0x02)

        # Keep alive
        keep_alive = struct.unpack("!H", payload[offset:offset + 2])[0] if offset + 2 <= len(payload) else 60
        offset += 2

        # Client ID
        client_id, consumed = _decode_utf8_string(payload, offset)
        offset += consumed

        # Will topic + message
        will_topic = ""
        will_message = ""
        if has_will:
            will_topic, consumed = _decode_utf8_string(payload, offset)
            offset += consumed
            will_message, consumed = _decode_utf8_string(payload, offset)
            offset += consumed

        # Username
        username = ""
        if has_username:
            username, consumed = _decode_utf8_string(payload, offset)
            offset += consumed

        # Password
        password = ""
        if has_password:
            password, consumed = _decode_utf8_string(payload, offset)
            offset += consumed

        event_data = {
            "stage": "connect",
            "protocol": proto_name,
            "protocol_level": proto_level,
            "client_id": client_id,
            "clean_session": clean_session,
            "keep_alive": keep_alive,
        }

        if username:
            event_data["username"] = username
        if password:
            event_data["password"] = password
        if has_will:
            event_data["will_topic"] = will_topic
            event_data["will_message"] = will_message

        if username or password:
            await self._log(session, EventType.AUTH_ATTEMPT, event_data)
        else:
            await self._log(session, EventType.REQUEST, event_data)

        # Accept all connections
        writer.write(_build_connack(0))
        await writer.drain()

    async def _handle_publish(self, session, payload: bytes, flags: int, writer):
        """Parse PUBLISH — extract topic and message payload (the C2 intel)."""
        qos = (flags >> 1) & 0x03
        retain = bool(flags & 0x01)
        offset = 0

        # Topic name
        topic, consumed = _decode_utf8_string(payload, offset)
        offset += consumed

        # Packet ID (only for QoS 1 and 2)
        packet_id = 0
        if qos > 0 and offset + 2 <= len(payload):
            packet_id = struct.unpack("!H", payload[offset:offset + 2])[0]
            offset += 2

        # Message payload — the actual C2 command / malware URL / payload
        message = payload[offset:]
        message_text = message.decode("utf-8", errors="replace")

        await self._log(session, EventType.COMMAND, {
            "action": "PUBLISH",
            "topic": topic,
            "message": message_text[:8192],
            "message_len": len(message),
            "qos": qos,
            "retain": retain,
            "message_hex": message[:256].hex() if not message_text.isprintable() else None,
        })

        # ACK for QoS 1
        if qos == 1 and packet_id:
            writer.write(_build_puback(packet_id))
            await writer.drain()

    async def _handle_subscribe(self, session, payload: bytes, writer):
        """Parse SUBSCRIBE — capture what topics the attacker is interested in."""
        offset = 0

        # Packet ID
        if offset + 2 > len(payload):
            return
        packet_id = struct.unpack("!H", payload[offset:offset + 2])[0]
        offset += 2

        topics = []
        granted_qos = []
        while offset < len(payload):
            topic, consumed = _decode_utf8_string(payload, offset)
            offset += consumed
            if offset < len(payload):
                qos = payload[offset]
                offset += 1
            else:
                qos = 0
            topics.append({"topic": topic, "qos": qos})
            granted_qos.append(min(qos, 2))

        await self._log(session, EventType.COMMAND, {
            "action": "SUBSCRIBE",
            "topics": topics,
        })

        writer.write(_build_suback(packet_id, granted_qos))
        await writer.drain()

    async def _handle_unsubscribe(self, session, payload: bytes, writer):
        """Parse UNSUBSCRIBE."""
        offset = 0
        if offset + 2 > len(payload):
            return
        packet_id = struct.unpack("!H", payload[offset:offset + 2])[0]
        offset += 2

        topics = []
        while offset < len(payload):
            topic, consumed = _decode_utf8_string(payload, offset)
            offset += consumed
            topics.append(topic)

        await self._log(session, EventType.REQUEST, {
            "action": "UNSUBSCRIBE",
            "topics": topics,
        })

        writer.write(_build_unsuback(packet_id))
        await writer.drain()
