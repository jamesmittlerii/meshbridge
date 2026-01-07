#!/usr/bin/env python3

import argparse
from meshtastic_mqtt_json import MeshtasticMQTT

# Register callbacks for specific message types
def on_text_message(json_data):
    print(f'Received text message: {json_data}')
    if "decoded" in json_data and "payload" in json_data["decoded"]:
        print(f'Text: {json_data["decoded"]["payload"]}')

def on_position(json_data):
    print(f'Position update: {json_data}')

def on_telemetry(json_data):
    print(f'Telemetry data: {json_data}')

def on_json(json_data):
    print(json_data)

def main():
    parser = argparse.ArgumentParser(description='Meshtastic MQTT Decoder using meshtastic-mqtt-json library')
    parser.add_argument('--host', required=True, help='MQTT broker host')
    parser.add_argument('--port', type=int, default=1883, help='MQTT broker port')
    parser.add_argument('--root', default='msh/US/2/e/', help='MQTT root topic')
    parser.add_argument('--channel', required=True, help='Channel name (e.g., PrivacyPls, MediumFast)')
    parser.add_argument('--username', help='MQTT username')
    parser.add_argument('--password', help='MQTT password')
    parser.add_argument('--psk', help='Pre-shared key for decryption (hex or base64)')
    
    args = parser.parse_args()
    
    # Create client instance
    client = MeshtasticMQTT()
    
    # Register callbacks
    client.register_callback('TEXT_MESSAGE_APP', on_json)
    client.register_callback('REPLY_APP', on_json)
    client.register_callback('PRIVATE_APP', on_json)
    client.register_callback('NODEINFO_APP', on_json)
    # NODEINFO_APP,PRIVATE_APP,REPLY_APP,TEXT_MESSAGE_APP
    #client.filters = "PRIVATE_APP,NODEINFO_APP,REPLY_APP,TEXT_MESSAGE_APP"
    client.filters = "TEXT_MESSAGE_APP"
        
    # Connect and start listening
    #print(f"Connecting to {args.host}:{args.port}...")
    #print(f"Subscribing to: {args.root}{args.channel}/#")
    
    client.connect(
        broker=args.host,
        port=args.port,
        root=args.root,
        channel=args.channel,
        username=args.username,
        password=args.password,
        key=args.psk
    )

if __name__ == "__main__":
    main()