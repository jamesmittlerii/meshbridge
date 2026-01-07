#!/usr/bin/env python3
import argparse
import sys
import time
import base64
import meshtastic
import meshtastic.tcp_interface
from meshtastic.protobuf import mesh_pb2, portnums_pb2
from pubsub import pub

def onReceive(packet, interface):
    """
    Callback for incoming packets.
    """
    try:
        # Debug: Print keys and raw packet to understand missing fields
        # print(f"DEBUG: Keys: {list(packet.keys())}")
        # print(f"DEBUG: Packet: {packet}")

        # We are interested in decoded packets
        if 'decoded' not in packet:
            return

        decoded = packet['decoded']
        portnum = decoded.get('portnum')
        
        # Normalize port_name: handle int or string
        if isinstance(portnum, int):
            try:
                port_name = portnums_pb2.PortNum.Name(portnum)
            except ValueError:
                port_name = f"UNKNOWN_APP_{portnum}"
        else:
            port_name = str(portnum)
        
        # Helper to format ID
        def get_node_id(key_int, key_str):
            if key_str: return key_str
            if key_int is not None: return f"!{key_int:08x}"
            return "UNKNOWN"

        from_str = get_node_id(packet.get('from'), packet.get('fromId'))
        to_str = get_node_id(packet.get('to'), packet.get('toId'))
        
        # Log Text Messages
        if port_name == 'TEXT_MESSAGE_APP':
            text = decoded.get('text')
            if not text:
                # Try decoding payload manually if text field is missing/empty
                payload = decoded.get('payload', b'')
                try:
                    text = payload.decode('utf-8')
                except:
                    text = f"<Binary: {len(payload)} bytes>"
            
            # Channel might be implicit 0 or missing
            channel = packet.get('channel', 0) 
            # Prepend newline to avoid being overwritten by lib logs
            print(f"\n[TEXT] Ch:{channel} From: {from_str}, To: {to_str}, Msg: {text}")
            
        # Log Node Info
        elif port_name == 'NODEINFO_APP':
            try:
                if 'user' in decoded:
                    user_info = decoded['user']
                    # Use the parsed ID from user object if available, it looks nicer
                    u_id = user_info.get('id', from_str)
                    long_name = user_info.get('longName', 'N/A')
                    short_name = user_info.get('shortName', 'N/A')
                    print(f"[NODEINFO] From: {from_str}, To: {to_str}, ID: {u_id}, Long: {long_name}, Short: {short_name}")
                else: # Fallback to parsing payload
                    payload = decoded.get('payload')
                    if payload:
                        u = mesh_pb2.User()
                        u.ParseFromString(payload)
                        print(f"[NODEINFO] From: {from_str}, To: {to_str}, ID: {u.id}, Long: {u.long_name}, Short: {u.short_name}")
            except Exception as e:
                print(f"[NODEINFO] Error parsing user: {e}")

    except Exception as e:
        print(f"Error processing packet: {e}")

def main():
    parser = argparse.ArgumentParser(description="Monitor Meshtastic Node via TCP")
    parser.add_argument("--host", required=True, help="IP address of the Meshtastic radio")
    args = parser.parse_args()

    print(f"Connecting to {args.host}...")
    
    interface = None
    try:
        interface = meshtastic.tcp_interface.TCPInterface(hostname=args.host)
        
        # Subscribe to receive messages
        pub.subscribe(onReceive, "meshtastic.receive")
        
        print("Connected and listening. Press Ctrl+C to stop.")
        
        # Keep alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nDisconnecting...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if interface:
            interface.close()

if __name__ == "__main__":
    main()
