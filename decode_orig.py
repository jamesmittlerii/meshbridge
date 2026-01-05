#!/usr/bin/env python3
"""
decode.py — Subscribe to Meshtastic MQTT topics and decode protobuf MeshPackets.
Optionally decrypt channel-encrypted payloads using a shared channel PSK (AES-CTR).

Examples:
  ./decode.py --host 192.168.4.187 --topic 'msh/US/#'
  ./decode.py --host 192.168.4.187 --topic 'msh/US/2/e/PrivacyPls/#' --psk '8AjRAxWcl/bdzZNbsxAK8g=='
  ./decode.py --host 192.168.4.187 --topic 'msh/US/#' --user meshdev --password large4cats
"""

import argparse
import base64
import binascii
from typing import Optional

import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from meshtastic.protobuf import mesh_pb2
from meshtastic.protobuf import portnums_pb2

# Some Meshtastic MQTT payloads are wrapped in a ServiceEnvelope
try:
    from meshtastic.protobuf import mqtt_pb2  # type: ignore
    HAVE_ENVELOPE = True
except Exception:
    HAVE_ENVELOPE = False


# -----------------------------
# Proto field helpers
# -----------------------------

def pkt_from(pkt) -> int:
    """Return MeshPacket.from across different codegens."""
    if hasattr(pkt, "from_"):
        return getattr(pkt, "from_")
    return getattr(pkt, "from")  # keyword, must getattr

def pkt_to(pkt) -> int:
    return getattr(pkt, "to")

def portnum_name(portnum: int) -> str:
    try:
        return portnums_pb2.PortNum.Name(portnum)
    except Exception:
        return str(portnum)


# -----------------------------
# Key parsing & crypto
# -----------------------------

def parse_psk(psk: str) -> bytes:
    """
    Accept PSK as:
      - hex with/without 0x
      - base64 (like '...==')
    """
    s = psk.strip()
    if s.startswith("0x"):
        s = s[2:]

    hexish = all(c in "0123456789abcdefABCDEF" for c in s) and (len(s) % 2 == 0)
    if hexish:
        return binascii.unhexlify(s)

    return base64.b64decode(s)

def _ctr_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    dec = cipher.decryptor()
    return dec.update(ciphertext) + dec.finalize()

def aes_ctr_decrypt_try(key: bytes, from_id: int, packet_id: int, ciphertext: bytes) -> Optional[bytes]:
    """
    Meshtastic channel encryption uses AES-CTR with an IV derived from packet id + sender id.
    Common layout (16 bytes):
      uint64(packet_id) || uint32(from_id) || uint32(0)
    We try a few safe variants and accept the first that parses as mesh_pb2.Data.
    """
    candidates: list[bytes] = []

    # Most likely layouts
    candidates.append(packet_id.to_bytes(8, "little") + from_id.to_bytes(4, "little") + (0).to_bytes(4, "little"))
    candidates.append(packet_id.to_bytes(8, "big")    + from_id.to_bytes(4, "big")    + (0).to_bytes(4, "big"))

    # Permutations sometimes seen
    candidates.append(from_id.to_bytes(4, "little") + packet_id.to_bytes(8, "little") + (0).to_bytes(4, "little"))
    candidates.append(from_id.to_bytes(4, "big")    + packet_id.to_bytes(8, "big")    + (0).to_bytes(4, "big"))

    # Fallback older 4+4+8 constructions
    candidates.append(from_id.to_bytes(4, "little") + packet_id.to_bytes(4, "little") + b"\x00" * 8)
    candidates.append(packet_id.to_bytes(4, "little") + from_id.to_bytes(4, "little") + b"\x00" * 8)
    candidates.append(from_id.to_bytes(4, "big") + packet_id.to_bytes(4, "big") + b"\x00" * 8)
    candidates.append(packet_id.to_bytes(4, "big") + from_id.to_bytes(4, "big") + b"\x00" * 8)

    for iv in candidates:
        try:
            pt = _ctr_decrypt(key, iv, ciphertext)
        except Exception:
            continue

        try:
            d = mesh_pb2.Data()
            d.ParseFromString(pt)
            if d.portnum != 0:
                return pt
        except Exception:
            pass

    return None


# -----------------------------
# Protobuf decode helpers
# -----------------------------

def try_decode_envelope(payload: bytes) -> Optional[mesh_pb2.MeshPacket]:
    if not HAVE_ENVELOPE:
        return None
    env = mqtt_pb2.ServiceEnvelope()
    try:
        env.ParseFromString(payload)
    except Exception:
        return None

    if hasattr(env, "packet") and env.packet:
        return env.packet
    return None

def try_decode_meshpacket(payload: bytes) -> Optional[mesh_pb2.MeshPacket]:
    pkt = mesh_pb2.MeshPacket()
    try:
        pkt.ParseFromString(payload)
        return pkt
    except Exception:
        return None

def extract_encrypted_bytes(pkt) -> Optional[bytes]:
    """
    Across versions, pkt.encrypted can be:
      - raw bytes
      - message with .payload
      - message with .ciphertext
    """
    if not pkt.HasField("encrypted"):
        return None

    enc = pkt.encrypted
    if isinstance(enc, (bytes, bytearray)):
        return bytes(enc)
    if hasattr(enc, "payload"):
        return enc.payload
    if hasattr(enc, "ciphertext"):
        return enc.ciphertext
    return None

def decode_inner_data(data_bytes: bytes) -> None:
    d = mesh_pb2.Data()
    d.ParseFromString(data_bytes)

    pn_name = portnum_name(d.portnum)
    print(f"  inner Data(portnum={pn_name} [{d.portnum}]) payload_len={len(d.payload)}")

    # Text is often just raw UTF-8 bytes
    if pn_name in ("TEXT_MESSAGE_APP", "TEXT_MESSAGE"):
        print(f"    text: {d.payload.decode('utf-8', errors='replace')}")
        return

    # Try protobuf decodes for common apps if present
    try:
        if pn_name == "NODEINFO_APP":
            from meshtastic.protobuf import nodeinfo_pb2
            ni = nodeinfo_pb2.NodeInfo()
            ni.ParseFromString(d.payload)
            print(f"    nodeinfo: {ni}")
            return

        if pn_name == "TELEMETRY_APP":
            from meshtastic.protobuf import telemetry_pb2
            t = telemetry_pb2.Telemetry()
            t.ParseFromString(d.payload)
            print(f"    telemetry: {t}")
            return

        if pn_name == "POSITION_APP":
            from meshtastic.protobuf import position_pb2
            p = position_pb2.Position()
            p.ParseFromString(d.payload)
            print(f"    position: {p}")
            return
    except Exception:
        # fall through to hex/text fallback
        pass

    # Fallback: if it looks like printable UTF-8, show it
    try:
        s = d.payload.decode("utf-8")
        if all((c in "\r\n\t") or (32 <= ord(c) <= 126) for c in s):
            print(f"    text?: {s}")
            return
    except Exception:
        pass

    print(f"    payload (hex): {d.payload.hex()}")


# -----------------------------
# MQTT callbacks (Callback API v2)
# -----------------------------

def on_connect(client, userdata, flags, reason_code, properties):
    topics = userdata["topics"]
    print(f"Connected rc={reason_code}. Subscribing to: {topics}")
    for t in topics:
        client.subscribe(t)

def on_message(client, userdata, msg):
    key: Optional[bytes] = userdata.get("key_bytes")
    raw = msg.payload

    pkt = try_decode_envelope(raw) or try_decode_meshpacket(raw)
    if pkt is None:
        print(f"{msg.topic}: <unrecognized payload> len={len(raw)}")
        return

    from_id = pkt_from(pkt)
    to_id = pkt_to(pkt)

    print(f"\nTopic: {msg.topic}")
    print(
        f"  from=!{from_id:08x}  to=!{to_id:08x} id={pkt.id}  chan={pkt.channel}  "
        f"hop_limit={pkt.hop_limit}  rx_snr={getattr(pkt, 'rx_snr', 0)}"
    )

    if pkt.HasField("decoded"):
        pn = portnum_name(pkt.decoded.portnum)
        print(f"  decoded(portnum={pn}) payload_len={len(pkt.decoded.payload)}")
        if pn in ("TEXT_MESSAGE_APP", "TEXT_MESSAGE"):
            print(f"    text: {pkt.decoded.payload.decode('utf-8', errors='replace')}")
        else:
            print(f"    payload (hex): {pkt.decoded.payload.hex()}")
        return

    ct = extract_encrypted_bytes(pkt)
    if ct is not None:
        print(f"  encrypted payload_len={len(ct)}")
        if not key:
            print("    (no PSK provided; cannot decrypt channel payload)")
            return

        pt = aes_ctr_decrypt_try(key, from_id, pkt.id, ct)
        if pt is None:
            print("    decrypt failed to produce a valid Data protobuf (wrong PSK or unknown IV layout)")
            return

        decode_inner_data(pt)
        return

    print("  (no decoded/encrypted field present)")


# -----------------------------
# Main
# -----------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True, help="MQTT broker IP/host")
    ap.add_argument("--port", type=int, default=1883)
    ap.add_argument("--topic", action="append", required=True,
                    help="Topic to subscribe (repeatable), e.g. 'msh/US/#'")
    ap.add_argument("--user", help="MQTT username (optional)")
    ap.add_argument("--password", help="MQTT password (optional)")
    ap.add_argument("--psk", help="Channel PSK (base64 or hex) to decrypt channel payloads (optional)")
    args = ap.parse_args()

    key_bytes = parse_psk(args.psk) if args.psk else None

    client = mqtt.Client(
        callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
        userdata={"topics": args.topic, "key_bytes": key_bytes},
    )
    client.on_connect = on_connect
    client.on_message = on_message

    if args.user:
        client.username_pw_set(args.user, args.password or "")

    client.connect(args.host, args.port, keepalive=60)
    client.loop_forever()


if __name__ == "__main__":
    main()
