#!/usr/bin/env python3
import argparse
import binascii
import sys
import time

import paho.mqtt.client as mqtt

# Meshtastic protobufs (packaged with meshtastic-python)
from meshtastic.protobuf import mqtt_pb2, mesh_pb2, portnums_pb2

def hex_bytes(b: bytes, maxlen: int = 80) -> str:
    h = binascii.hexlify(b).decode("ascii")
    if len(h) > maxlen:
        return h[:maxlen] + "…"
    return h

def try_decode_payload(decoded):
    """
    decoded is meshtastic.Data (MeshPacket.decoded)
    """
    port = decoded.portnum
    payload = decoded.payload

    port_name = portnums_pb2.PortNum.Name(port) if port in portnums_pb2.PortNum.values() else str(port)

    # Try a few common app payload decodes.
    # If they don't parse, we'll just return None and show raw bytes.
    if port == portnums_pb2.PortNum.NODEINFO_APP:
        # NODEINFO typically carries a "User" message (id/names/hw/publicKey, etc.)
        u = mesh_pb2.User()
        u.ParseFromString(payload)
        return ("User(NODEINFO_APP)", u)

    if port == portnums_pb2.PortNum.POSITION_APP:
        p = mesh_pb2.Position()
        p.ParseFromString(payload)
        return ("Position", p)

    if port == portnums_pb2.PortNum.TELEMETRY_APP:
        t = mesh_pb2.Telemetry()
        t.ParseFromString(payload)
        return ("Telemetry", t)

    # Text messages can be raw UTF-8 (depending on which text app)
    if port in (portnums_pb2.PortNum.TEXT_MESSAGE_APP, portnums_pb2.PortNum.TEXT_MESSAGE_COMPRESSED_APP):
        try:
            return ("Text", payload.decode("utf-8", errors="replace"))
        except Exception:
            pass

    return ("RawPayload", None)

import json
import base64

def on_message(client, userdata, msg: mqtt.MQTTMessage):
    topic = msg.topic
    raw = msg.payload

    env = mqtt_pb2.ServiceEnvelope()
    try:
        env.ParseFromString(raw)
    except Exception as e:
        print(json.dumps({
            "topic": topic,
            "error": "Not a ServiceEnvelope",
            "error_details": str(e),
            "raw_hex": hex_bytes(raw)
        }))
        return

    pkt = env.packet  # MeshPacket
    
    # Build the packet dictionary
    packet_data = {
        "to": pkt.to,
        "id": pkt.id,
        "hop_limit": pkt.hop_limit,
        "want_ack": pkt.want_ack,
        "channel": pkt.channel,
        "rx_time": pkt.rx_time,
        "rx_snr": pkt.rx_snr,
        "priority": pkt.priority
    }
    
    # Handle 'from' field safely
    try:
        packet_data["from"] = pkt.from_
    except AttributeError:
        packet_data["from"] = getattr(pkt, "from")

    output = {
        "timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        "topic": topic,
        "channel_id": env.channel_id,
        "gateway_id": env.gateway_id,
        "packet": packet_data
    }

    if pkt.HasField("decoded"):
        d = pkt.decoded
        port = d.portnum
        port_name = portnums_pb2.PortNum.Name(port) if port in portnums_pb2.PortNum.values() else str(port)
        
        decoded_data = {
            "portnum": port,
            "portname": port_name,
            "payload_len": len(d.payload),
            "payload_base64": base64.b64encode(d.payload).decode('ascii')
        }

        kind, obj = try_decode_payload(d)
        decoded_data["type"] = kind
        
        if isinstance(obj, str):
            decoded_data["text"] = obj
        elif obj is not None:
            # Convert protobuf to dict/string if possible, or just string representation
            decoded_data["protobuf"] = str(obj) # Simple string dump for now
            
            # Specific handling for known types to extract useful fields
            if kind == "User(NODEINFO_APP)":
                 decoded_data["user_id"] = obj.id
                 decoded_data["long_name"] = obj.long_name
                 decoded_data["short_name"] = obj.short_name
                 decoded_data["hw_model"] = mesh_pb2.HardwareModel.Name(obj.hw_model)
                 if obj.public_key:
                     decoded_data["public_key"] = base64.b64encode(obj.public_key).decode('ascii')
            elif kind == "Position":
                decoded_data["latitude"] = obj.latitude_i / 1e7
                decoded_data["longitude"] = obj.longitude_i / 1e7
        
        output["decoded"] = decoded_data
        
    else:
        # If still encrypted
        if pkt.encrypted:
            output["encrypted"] = {
                "len": len(pkt.encrypted),
                "ciphertext_base64": base64.b64encode(pkt.encrypted).decode('ascii')
            }
        else:
            output["status"] = "No payload"

    print(json.dumps(output))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=1883)
    ap.add_argument("--user")
    ap.add_argument("--password")
    ap.add_argument("--topic", default="msh/#")
    args = ap.parse_args()

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    if args.user:
        client.username_pw_set(args.user, args.password or "")

    client.on_message = on_message
    client.connect(args.host, args.port, keepalive=60)
    client.subscribe(args.topic)

    print(f"subscribed to {args.topic} on {args.host}:{args.port}")
    client.loop_forever()

if __name__ == "__main__":
    main()