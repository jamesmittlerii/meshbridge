#!/usr/bin/env python3
import meshtastic
import meshtastic.tcp_interface
import sys
import time

import datetime

# --- CONFIGURATION ---
HOST_IP = '192.168.4.217'        # IP of the sender node
DESTINATION_ID = '!69854258'    # Node ID of the recipient
TEST_CHANNEL_INDEX = 6          # Channel index to force
MESSAGE_BASE = "DM via TCP (Fire and Forget)"

def send_dm():
    print(f"Connecting to {HOST_IP}...")
    
    # Add timestamp
    text_to_send = f"{MESSAGE_BASE} at {datetime.datetime.now().strftime('%H:%M:%S')}"
    
    interface = None
    try:
        # Connect to the interface
        interface = meshtastic.tcp_interface.TCPInterface(hostname=HOST_IP)
        
        print(f"Connected. Sending DM to {DESTINATION_ID} on Index {TEST_CHANNEL_INDEX}...")
        
        # Send the message
        packet = interface.sendText(
            text=text_to_send,
            destinationId=DESTINATION_ID,
            wantAck=True,
            channelIndex=TEST_CHANNEL_INDEX
        )
        
        # Determine the ID of the packet we just sent
        sent_id = packet.id if hasattr(packet, 'id') else "Unknown"
        print(f"Message sent (Internal ID: {sent_id}).")
        
        # Give a small moment for the command to flush if needed, usually close() handles it
        time.sleep(1) 
            
    except KeyboardInterrupt:
        print("\nUser cancelled.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if interface:
            interface.close()
        print("Connection closed.")

if __name__ == "__main__":
    send_dm()