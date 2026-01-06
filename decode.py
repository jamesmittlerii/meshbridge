#!/usr/bin/env python3
"""
Meshtastic MQTT Packet Decoder with JSON output.
Connects to an MQTT broker, decodes Meshtastic packets, and outputs them as JSON.
"""

import argparse
import base64
import binascii
import json
import sys
from typing import Optional, Dict, Any
from datetime import datetime

import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

try:
    from meshtastic.protobuf import mqtt_pb2, mesh_pb2, portnums_pb2
except ImportError:
    print("Error: meshtastic package not found. Install with: pip install meshtastic", file=sys.stderr)
    sys.exit(1)


def parse_psk(psk_string: str) -> Optional[bytes]:
    """
    Parse a PSK from hex or base64 format.
    
    Args:
        psk_string: PSK as hex (with or without 0x prefix) or base64
        
    Returns:
        PSK as bytes, or None if parsing fails
    """
    if not psk_string:
        return None
        
    s = psk_string.strip()
    
    # Try hex first
    if s.startswith("0x") or s.startswith("0X"):
        s = s[2:]
    
    # Check if it looks like hex
    if all(c in "0123456789abcdefABCDEF" for c in s) and len(s) % 2 == 0:
        try:
            return binascii.unhexlify(s)
        except Exception:
            pass
    
    # Handle Meshtastic MQTT encryption key substitution
    # When mqtt.encryption_enabled is true, 1-byte PSKs are replaced with the MQTT encryption key
    # The pattern is: take the MQTT base key and replace the last byte with the PSK byte
    if len(s) <= 4 and base64.b64decode(s.strip()) and len(base64.b64decode(s.strip())) == 1:
        # This is a 1-byte PSK - use MQTT encryption key pattern
        psk_byte = base64.b64decode(s.strip())[0]
        # Base MQTT key: 1PG7OiApB1nwvP+rz05pAQ== but with last byte replaced
        mqtt_key_base = base64.b64decode('1PG7OiApB1nwvP+rz05pAQ==')
        mqtt_key = mqtt_key_base[:-1] + bytes([psk_byte])
        s = base64.b64encode(mqtt_key).decode('ascii')
        print(f"INFO: Substituting 1-byte PSK with MQTT encryption key", file=sys.stderr)
    
    # Try base64
    try:
        return base64.b64decode(s)
    except Exception as e:
        print(f"Warning: Failed to parse PSK: {e}", file=sys.stderr)
        return None


def decrypt_packet(encrypted_data: bytes, packet_id: int, from_node: int, psk: bytes) -> Optional[bytes]:
    """
    Decrypt an encrypted Meshtastic packet using AES-CTR.
    Tries multiple IV permutations to handle different firmware versions.
    
    Args:
        encrypted_data: The encrypted payload
        packet_id: Packet ID
        from_node: Sender node ID
        psk: Pre-shared key (as-is, no padding)
        
    Returns:
        Decrypted data as bytes, or None if decryption fails
    """
    if not encrypted_data or not psk:
        return None
    
    # Pad short keys to minimum AES key size (16 bytes for AES-128)
    if len(psk) < 16:
        psk = psk + b'\x00' * (16 - len(psk))
        print(f"DEBUG: Padded PSK to {len(psk)} bytes: {psk.hex()}", file=sys.stderr)
    
    # Use PSK as-is (no padding) - AES will work with 1-byte, 16-byte, or 32-byte keys
    # Generate candidate IVs (nonces) - different firmware versions use different layouts
    packet_id_bytes_le = packet_id.to_bytes(8, byteorder='little')
    packet_id_bytes_be = packet_id.to_bytes(8, byteorder='big')
    from_node_bytes_le = from_node.to_bytes(8, byteorder='little')
    from_node_bytes_be = from_node.to_bytes(8, byteorder='big')
    
    candidates = [
        packet_id_bytes_le[:4] + from_node_bytes_le[:4] + b'\x00' * 8,
        packet_id_bytes_be[:4] + from_node_bytes_be[:4] + b'\x00' * 8,
        packet_id_bytes_le + from_node_bytes_le,
        packet_id_bytes_be + from_node_bytes_be,
        from_node_bytes_le + packet_id_bytes_le,
        from_node_bytes_be + packet_id_bytes_be,
    ]
    
    # Try each IV candidate
    for nonce in candidates:
        try:
            cipher = Cipher(
                algorithms.AES(psk),
                modes.CTR(nonce),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Validate by trying to parse as Data protobuf
            try:
                data = mesh_pb2.Data()
                data.ParseFromString(decrypted)
                return decrypted
            except Exception:
                continue
                
        except Exception:
            continue
    
    return None


def format_node_id(node_id: int) -> str:
    """Format a node ID as !hex string."""
    return f"!{node_id:08x}"


def get_portnum_name(portnum: int) -> str:
    """Get the human-readable name for a portnum."""
    try:
        return portnums_pb2.PortNum.Name(portnum)
    except Exception:
        return f"UNKNOWN_{portnum}"


def extract_encrypted_bytes(packet) -> Optional[bytes]:
    """Extract encrypted bytes from a packet, handling different field names."""
    enc = getattr(packet, 'encrypted', None)
    if enc:
        if isinstance(enc, (bytes, bytearray)):
            return bytes(enc)
        if hasattr(enc, 'payload'):
            return enc.payload
        if hasattr(enc, 'ciphertext'):
            return enc.ciphertext
    return None


def pkt_from(pkt) -> int:
    """Extract 'from' field, handling both 'from' and 'from_' field names."""
    return getattr(pkt, 'from', None) or getattr(pkt, 'from_', 0)


def pkt_to(pkt) -> int:
    """Extract 'to' field."""
    return getattr(pkt, 'to', 0)


def decode_packet_to_json(payload: bytes, psk: Optional[bytes]) -> Optional[Dict[str, Any]]:
    """
    Decode a Meshtastic packet payload and return as a JSON-serializable dict.
    
    Args:
        payload: Raw MQTT payload bytes
        psk: Optional decryption key
        
    Returns:
        Dictionary containing decoded packet data, or None if parsing fails
    """
    # Try to parse as ServiceEnvelope first
    envelope = None
    packet = None
    
    try:
        # Debug: Print raw payload in base64
        import base64
        # print(f"DEBUG: RAW_PAYLOAD_B64: {base64.b64encode(payload).decode('ascii')}", file=sys.stderr)
        
        envelope = mqtt_pb2.ServiceEnvelope()
        envelope.ParseFromString(payload)
        if envelope.HasField('packet'):
            packet = envelope.packet
    except Exception:
        pass
    
    # Fall back to direct MeshPacket parsing
    if not packet:
        try:
            packet = mesh_pb2.MeshPacket()
            packet.ParseFromString(payload)
        except Exception:
            return None
    
    if not packet:
        return None
    
    # Build result dictionary
    result: Dict[str, Any] = {
        'raw': base64.b64encode(payload).decode('ascii'),
        'from': format_node_id(pkt_from(packet)),
        'to': format_node_id(pkt_to(packet)),
        'id': packet.id if packet.id else None,
        'channel': packet.channel if packet.channel else 0,
        'hop_limit': packet.hop_limit if packet.hop_limit else None,
        'hop_start': packet.hop_start if packet.hop_start else None,
        'rx_time': packet.rx_time if packet.rx_time else None,
        'rx_snr': packet.rx_snr if packet.rx_snr else None,
        'rx_rssi': packet.rx_rssi if packet.rx_rssi else None,
    }
    
    # Add timestamp if available
    if packet.rx_time:
        result['timestamp'] = datetime.fromtimestamp(packet.rx_time).isoformat() + 'Z'
    
    # Add envelope metadata if available
    if envelope:
        if envelope.channel_id:
            result['channel_id'] = envelope.channel_id
        if envelope.gateway_id:
            result['gateway_id'] = envelope.gateway_id
    
    # Handle encrypted or decoded data
    encrypted_bytes = extract_encrypted_bytes(packet)
    
    if encrypted_bytes and psk:
        # Debug output
        # print(f"DEBUG: Encrypted payload hex: {encrypted_bytes.hex()}", file=sys.stderr)
        # print(f"DEBUG: PSK hex: {psk.hex()}", file=sys.stderr)
        # print(f"DEBUG: Packet ID: {packet.id}, From: {pkt_from(packet):08x}", file=sys.stderr)
        
        # Attempt decryption
        decrypted = decrypt_packet(encrypted_bytes, packet.id, pkt_from(packet), psk)
        
        if decrypted:
            try:
                data = mesh_pb2.Data()
                data.ParseFromString(decrypted)
                
                result['encrypted'] = True
                result['decrypted'] = True
                result['portnum'] = get_portnum_name(data.portnum)
                
                # Extract payload based on type
                if result['portnum'] == 'NODEINFO_APP':
                    try:
                        user = mesh_pb2.User()
                        user.ParseFromString(data.payload)
                        # Create a serializable dictionary
                        user_dict = {
                            'id': user.id,
                            'longName': user.long_name,
                            'shortName': user.short_name,
                            'macaddr': base64.b64encode(user.macaddr).decode('ascii') if user.macaddr else None,
                            'hwModel': mesh_pb2.HardwareModel.Name(user.hw_model),
                            'publicKey': base64.b64encode(user.public_key).decode('ascii') if user.public_key else None,
                        }
                        result['payload'] = user_dict
                    except Exception as e:
                         result['payload'] = f"Failed to parse NodeInfo: {e}"
                elif data.portnum == portnums_pb2.TEXT_MESSAGE_APP:
                    try:
                        result['payload'] = data.payload.decode('utf-8', errors='replace')
                    except Exception:
                        result['payload'] = base64.b64encode(data.payload).decode('ascii')
                else:
                    result['payload'] = base64.b64encode(data.payload).decode('ascii')
                    
            except Exception as e:
                result['encrypted'] = True
                result['decrypted'] = False
                result['error'] = f"Failed to parse decrypted data: {e}"
        else:
            result['encrypted'] = True
            result['decrypted'] = False
            result['error'] = "Decryption failed"
            
    elif packet.HasField('decoded'):
        # Already decoded packet
        data = packet.decoded
        result['encrypted'] = False
        result['portnum'] = get_portnum_name(data.portnum)
        
        if result['portnum'] == 'NODEINFO_APP':
            try:
                user = mesh_pb2.User()
                user.ParseFromString(data.payload)
                # Create a serializable dictionary
                user_dict = {
                    'id': user.id,
                    'longName': user.long_name,
                    'shortName': user.short_name,
                    'macaddr': base64.b64encode(user.macaddr).decode('ascii') if user.macaddr else None,
                    'hwModel': mesh_pb2.HardwareModel.Name(user.hw_model),
                    'publicKey': base64.b64encode(user.public_key).decode('ascii') if user.public_key else None,
                }
                result['payload'] = user_dict
            except Exception as e:
                    result['payload'] = f"Failed to parse NodeInfo: {e}"
        elif data.portnum == portnums_pb2.TEXT_MESSAGE_APP:
            try:
                result['payload'] = data.payload.decode('utf-8', errors='replace')
            except Exception:
                result['payload'] = base64.b64encode(data.payload).decode('ascii')
        else:
            result['payload'] = base64.b64encode(data.payload).decode('ascii')
    else:
        result['encrypted'] = bool(encrypted_bytes)
        result['decrypted'] = False
        if not psk and encrypted_bytes:
            result['error'] = "No PSK provided for encrypted packet"
    
    return result


def on_connect(client, userdata, flags, reason_code, properties):
    """MQTT connect callback (v2 API)."""
    topics = userdata['topics']
    print(f"INFO: Connected (rc={reason_code}). Subscribing to: {topics}", file=sys.stderr)
    for topic in topics:
        client.subscribe(topic)


def on_disconnect(client, userdata, flags, reason_code, properties):
    """MQTT disconnect callback (v2 API)."""
    if reason_code != 0:
        print(f"WARN: Unexpected disconnection (code {reason_code}). Reconnecting...", file=sys.stderr)


def on_message(client, userdata, msg):
    """MQTT message callback."""
    psk = userdata.get('psk')
    
    result = decode_packet_to_json(msg.payload, psk)
    
    if result:
        # Add topic to output
        result['topic'] = msg.topic
        # Output as JSON to stdout (flushed immediately)
        # Use simple format (not indented) for easier line-processing if desired, 
        # or keep indent=2 for readability. User likely wants line-based JSON for piping usually,
        # but indent is fine if jq handles it.
        print(json.dumps(result, indent=2), file=sys.stdout, flush=True)
    else:
        print(json.dumps({
            'topic': msg.topic,
            'error': 'Failed to parse packet',
            'payload_length': len(msg.payload)
        }), file=sys.stderr)


def load_env_file():
    """Simple .env file loader."""
    env_vars = {}
    try:
        with open('.env', 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' in line:
                    key, value = line.split('=', 1)
                    env_vars[key.strip()] = value.strip()
    except FileNotFoundError:
        pass
    return env_vars

def main():
    """Main entry point."""
    # Load environment variables
    env = load_env_file()
    
    parser = argparse.ArgumentParser(description='Meshtastic MQTT Packet Decoder (JSON output)')
    parser.add_argument('--host', default=env.get('MQTT_HOST'), help='MQTT broker host')
    parser.add_argument('--port', type=int, default=int(env.get('MQTT_PORT', 1883)), help='MQTT broker port')
    
    # Handle topics default
    default_topics = env.get('MQTT_TOPICS', '').split(',') if env.get('MQTT_TOPICS') else None
    parser.add_argument('--topic', action='append', dest='topics', default=default_topics,
                        help='MQTT topic to subscribe to (can be specified multiple times)')
                        
    parser.add_argument('--psk', default=env.get('MESHTASTIC_PSK'), help='Pre-shared key for decryption (hex or base64)')
    parser.add_argument('--username', default=env.get('MQTT_USERNAME'), help='MQTT username')
    parser.add_argument('--password', default=env.get('MQTT_PASSWORD'), help='MQTT password')
    
    args = parser.parse_args()
    
    # Validate required args if not supplied via env or cli
    if not args.host:
        parser.error("--host is required (or set MQTT_HOST in .env)")
    if not args.topics:
        parser.error("--topic is required (or set MQTT_TOPICS in .env)")
    
    # Parse PSK if provided
    psk = None
    if args.psk:
        psk = parse_psk(args.psk)
        if not psk:
            print("Error: Invalid PSK format", file=sys.stderr)
            sys.exit(1)
    
    # Create MQTT client with v2 callback API
    client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        userdata={
            'topics': args.topics,
            'psk': psk
        }
    )
    
    # Set callbacks
    client.on_connect = on_connect
    client.on_message = on_message
    client.on_disconnect = on_disconnect
    
    # Set credentials if provided
    if args.username:
        client.username_pw_set(args.username, args.password)
    
    # Connect and loop
    try:
        print(f"INFO: Connecting to {args.host}:{args.port}...", file=sys.stderr)
        client.connect(args.host, args.port, 60)
        client.loop_forever()
    except KeyboardInterrupt:
        print("\nINFO: Disconnecting...", file=sys.stderr)
        client.disconnect()
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
