#!/usr/bin/env python3
"""
Meshtastic MQTT Packet Decoder

Subscribes to MQTT broker and decodes Meshtastic packets.
Handles encrypted packets with optional PSK.
"""

import argparse
import base64
import sys
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import paho.mqtt.client as mqtt

# Import Meshtastic protobuf definitions
try:
    from meshtastic import mqtt_pb2, mesh_pb2, portnums_pb2
except ImportError:
    print("Error: meshtastic package not found. Install with: pip install meshtastic", file=sys.stderr)
    sys.exit(1)


def parse_psk(psk_string):
    """
    Parse PSK from various formats: base64, hex (0x...), or plain hex.
    Returns bytes or None if parsing fails.
    """
    if not psk_string:
        return None
    
    try:
        # Try hex with 0x prefix
        if psk_string.startswith('0x') or psk_string.startswith('0X'):
            return bytes.fromhex(psk_string[2:])
        
        # Try plain hex (common for Meshtastic)
        try:
            return bytes.fromhex(psk_string)
        except ValueError:
            pass
        
        # Try base64
        return base64.b64decode(psk_string)
    except Exception as e:
        print(f"Warning: Failed to parse PSK: {e}", file=sys.stderr)
        return None


def decrypt_packet(encrypted_data, packet_id, from_node, psk):
    """
    Decrypt Meshtastic packet using AES-CTR with channel PSK.
    
    Meshtastic uses AES-256-CTR with a nonce derived from:
    - packet_id (4 bytes)
    - from_node (4 bytes)
    - Padded to 16 bytes with zeros
    """
    if not psk or len(psk) == 0:
        return None
    
    try:
        # Ensure PSK is 32 bytes (AES-256), pad or truncate if needed
        # Note: Meshtastic typically uses "AQ==" (base64 for 0x01) as default key
        key = psk.ljust(32, b'\x00')[:32]
        
        # Construct nonce: packet_id (4) + from_node (4) + padding (8)
        nonce = packet_id.to_bytes(4, 'little') + from_node.to_bytes(4, 'little') + b'\x00' * 8
        
        # Decrypt using AES-256-CTR
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
        
        return decrypted
    except Exception as e:
        print(f"  Decryption failed: {e}", file=sys.stderr)
        return None


def format_node_id(node_id):
    """Format node ID as Meshtastic-style hex: !69854258"""
    if isinstance(node_id, str):
        # Already formatted or needs parsing
        if node_id.startswith('!'):
            return node_id
        # Try to parse as hex string
        try:
            node_id = int(node_id, 16)
        except ValueError:
            return node_id
    return f"!{node_id:08x}"


def decode_meshtastic_packet(payload, psk=None):
    """
    Decode a Meshtastic ServiceEnvelope from MQTT payload.
    Returns a dict with decoded information or None on failure.
    """
    try:
        # Parse the ServiceEnvelope (outer MQTT wrapper)
        envelope = mqtt_pb2.ServiceEnvelope()
        envelope.ParseFromString(payload)
        
        # Extract the MeshPacket
        packet = envelope.packet
        
        # Note: 'from' is a Python keyword, so we use getattr() to access the protobuf field
        # These should be uint32 values in the protobuf
        from_id = getattr(packet, 'from', 0)
        to_id = getattr(packet, 'to', 0xffffffff)
        
        # Ensure they are integers (protobuf should return int, but be defensive)
        if not isinstance(from_id, int):
            try:
                from_id = int(from_id)
            except (ValueError, TypeError):
                from_id = 0
        if not isinstance(to_id, int):
            try:
                to_id = int(to_id)
            except (ValueError, TypeError):
                to_id = 0xffffffff
        
        # Debug: if from_id is 0, print packet info to help diagnose
        if from_id == 0:
            print(f"  DEBUG: from_id is 0. Packet fields: {packet.ListFields()[:5]}", file=sys.stderr)
        
        result = {
            'from': format_node_id(from_id),
            'to': format_node_id(to_id),
            'channel': envelope.channel_id,  # Scalar field, no HasField() needed
            'gateway': format_node_id(envelope.gateway_id) if envelope.gateway_id else None,
        }
        
        # Check if packet is encrypted
        if packet.HasField('encrypted') and len(packet.encrypted) > 0:
            if psk:
                # Attempt decryption
                decrypted = decrypt_packet(
                    packet.encrypted,
                    packet.id,
                    from_id,  # Use the from_id we extracted earlier
                    psk
                )
                
                if decrypted:
                    # Parse decrypted Data protobuf
                    try:
                        data = mesh_pb2.Data()
                        data.ParseFromString(decrypted)
                        result['encrypted'] = True
                        result['data'] = data
                    except Exception as e:
                        # Decryption produced data but it's not valid protobuf
                        # This likely means wrong PSK or corrupted packet
                        result['encrypted'] = True
                        result['decrypt_failed'] = True
                        result['error'] = f'Decryption succeeded but Data parse failed: {e}'
                        result['decrypted_hex'] = decrypted[:32].hex() + ('...' if len(decrypted) > 32 else '')
                        return result
                else:
                    result['encrypted'] = True
                    result['decrypt_failed'] = True
                    return result
            else:
                result['encrypted'] = True
                result['no_psk'] = True
                return result
        elif packet.HasField('decoded'):
            # Packet is already decoded
            result['encrypted'] = False
            result['data'] = packet.decoded
        else:
            result['error'] = 'No payload (neither encrypted nor decoded)'
            return result
        
        # Decode the Data protobuf payload if present
        if 'data' in result:
            data = result['data']
            result['portnum'] = portnums_pb2.PortNum.Name(data.portnum) if data.portnum else 'UNKNOWN'
            
            # Decode specific payload types
            if data.portnum == portnums_pb2.PortNum.TEXT_MESSAGE_APP:
                result['text'] = data.payload.decode('utf-8', errors='replace')
            elif data.portnum == portnums_pb2.PortNum.POSITION_APP:
                pos = mesh_pb2.Position()
                pos.ParseFromString(data.payload)
                result['position'] = {
                    'lat': pos.latitude_i * 1e-7 if pos.latitude_i else None,
                    'lon': pos.longitude_i * 1e-7 if pos.longitude_i else None,
                    'alt': pos.altitude if pos.altitude else None,
                }
            elif data.portnum == portnums_pb2.PortNum.NODEINFO_APP:
                nodeinfo = mesh_pb2.User()
                nodeinfo.ParseFromString(data.payload)
                result['nodeinfo'] = {
                    'id': nodeinfo.id if nodeinfo.id else None,
                    'longname': nodeinfo.long_name if nodeinfo.long_name else None,
                    'shortname': nodeinfo.short_name if nodeinfo.short_name else None,
                }
            elif data.portnum == portnums_pb2.PortNum.TELEMETRY_APP:
                telemetry = mesh_pb2.Telemetry()
                telemetry.ParseFromString(data.payload)
                result['telemetry'] = {}
                if telemetry.HasField('device_metrics'):
                    result['telemetry']['battery'] = telemetry.device_metrics.battery_level
                if telemetry.HasField('environment_metrics'):
                    result['telemetry']['temp'] = telemetry.environment_metrics.temperature
            else:
                # Unknown portnum, show raw hex
                result['payload_hex'] = data.payload.hex() if data.payload else None
        
        return result
        
    except Exception as e:
        return {'error': f'Decode error: {e}'}


def print_packet(topic, packet_info):
    """Print decoded packet information in a readable format."""
    print(f"\n{'='*80}")
    print(f"Topic: {topic}")
    
    # Header line with from/to
    from_id = packet_info.get('from', '!unknown')
    to_id = packet_info.get('to', '!unknown')
    channel = packet_info.get('channel', 0)
    gateway = packet_info.get('gateway')
    
    header = f"From: {from_id} → To: {to_id} | Channel: {channel}"
    if gateway:
        header += f" | Gateway: {gateway}"
    print(header)
    
    # Handle errors
    if 'error' in packet_info:
        print(f"  Error: {packet_info['error']}")
        # Show decrypted hex if present (helps diagnose wrong PSK)
        if 'decrypted_hex' in packet_info:
            print(f"  Decrypted data (likely wrong PSK): {packet_info['decrypted_hex']}")
        return
    
    # Encryption status
    if packet_info.get('encrypted'):
        if packet_info.get('decrypt_failed'):
            print("  [ENCRYPTED - Decryption failed]")
            if 'decrypted_hex' in packet_info:
                print(f"  Decrypted data (likely wrong PSK): {packet_info['decrypted_hex']}")
            return
        elif packet_info.get('no_psk'):
            print("  [ENCRYPTED - No PSK provided]")
            return
        else:
            print("  [ENCRYPTED - Decrypted successfully]")
    
    # Port number
    portnum = packet_info.get('portnum', 'UNKNOWN')
    print(f"  PortNum: {portnum}")
    
    # Payload-specific information
    if 'text' in packet_info:
        print(f"  Text: {packet_info['text']}")
    elif 'position' in packet_info:
        pos = packet_info['position']
        print(f"  Position: lat={pos['lat']}, lon={pos['lon']}, alt={pos['alt']}")
    elif 'nodeinfo' in packet_info:
        info = packet_info['nodeinfo']
        print(f"  NodeInfo: {info['longname']} ({info['shortname']}) - {info['id']}")
    elif 'telemetry' in packet_info:
        telem = packet_info['telemetry']
        print(f"  Telemetry: {telem}")
    elif 'payload_hex' in packet_info:
        payload_hex = packet_info['payload_hex']
        preview = payload_hex[:64] + ('...' if len(payload_hex) > 64 else '')
        print(f"  Payload (hex): {preview}")


def on_connect(client, userdata, flags, rc):
    """MQTT connection callback."""
    if rc == 0:
        print("Connected to MQTT broker successfully")
        topics = userdata['topics']
        for topic in topics:
            client.subscribe(topic)
            print(f"Subscribed to: {topic}")
    else:
        print(f"Connection failed with code {rc}", file=sys.stderr)
        sys.exit(1)


def on_message(client, userdata, msg):
    """MQTT message callback - decode and print each packet."""
    psk = userdata.get('psk')
    
    try:
        packet_info = decode_meshtastic_packet(msg.payload, psk)
        if packet_info:
            print_packet(msg.topic, packet_info)
        else:
            print(f"\nTopic: {msg.topic}")
            print("  Error: Failed to decode packet (returned None)")
    except Exception as e:
        # Never crash - print error and continue
        print(f"\nTopic: {msg.topic}")
        print(f"  Error: Unexpected exception: {e}")


def on_disconnect(client, userdata, rc):
    """MQTT disconnect callback."""
    if rc != 0:
        print(f"Unexpected disconnection (code {rc}). Reconnecting...", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description='Decode Meshtastic MQTT packets from Mosquitto broker',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Required arguments
    parser.add_argument('--host', required=True, help='MQTT broker hostname or IP')
    parser.add_argument('--topic', action='append', required=True, 
                       help='MQTT topic to subscribe to (can specify multiple times)')
    
    # Optional arguments
    parser.add_argument('--port', type=int, default=1883, help='MQTT broker port (default: 1883)')
    parser.add_argument('--user', help='MQTT username for authentication')
    parser.add_argument('--password', help='MQTT password for authentication')
    parser.add_argument('--psk', help='Channel PSK for decryption (base64, hex, or 0x-prefixed hex)')
    
    args = parser.parse_args()
    
    # Parse PSK if provided
    psk = parse_psk(args.psk) if args.psk else None
    if args.psk and psk is None:
        print("Warning: PSK provided but could not be parsed", file=sys.stderr)
    
    # Create MQTT client
    client = mqtt.Client(userdata={
        'topics': args.topic,
        'psk': psk
    })
    
    # Set callbacks
    client.on_connect = on_connect
    client.on_message = on_message
    client.on_disconnect = on_disconnect
    
    # Set authentication if provided
    if args.user and args.password:
        client.username_pw_set(args.user, args.password)
    
    # Connect to broker
    print(f"Connecting to MQTT broker at {args.host}:{args.port}...")
    try:
        client.connect(args.host, args.port, keepalive=60)
    except Exception as e:
        print(f"Error connecting to broker: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Start the MQTT loop (blocking)
    print("Listening for messages... (Ctrl+C to exit)")
    try:
        client.loop_forever()
    except KeyboardInterrupt:
        print("\nExiting...")
        client.disconnect()


if __name__ == '__main__':
    main()
