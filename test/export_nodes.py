#!/usr/bin/env python3
"""
Export Meshtastic node database as JSON.
"""

import json
import sys
import base64
import meshtastic.tcp_interface

# Get host from command line or use default
host = sys.argv[1] if len(sys.argv) > 1 else "192.168.4.218"

print(f"Connecting to {host}...", file=sys.stderr)
iface = meshtastic.tcp_interface.TCPInterface(host)

# Wait a moment for node database to load
import time
time.sleep(2)

nodes = iface.nodes
print(f"Found {len(nodes)} nodes", file=sys.stderr)

# Convert to JSON-serializable format
node_list = []
for node_id, node_info in nodes.items():
    user = node_info.get('user', {})
    
    # Convert public key bytes to base64 if present
    pubkey = user.get('publicKey')
    if pubkey:
        if isinstance(pubkey, bytes):
            pubkey_b64 = base64.b64encode(pubkey).decode('ascii')
        else:
            pubkey_b64 = str(pubkey)
    else:
        pubkey_b64 = None
    
    # Handle macaddr - might be bytes or already a string
    macaddr = user.get('macaddr')
    if macaddr:
        if isinstance(macaddr, bytes):
            macaddr_b64 = base64.b64encode(macaddr).decode('ascii')
        else:
            macaddr_b64 = str(macaddr)
    else:
        macaddr_b64 = None
    
    node_data = {
        'num': node_id,
        'id': user.get('id'),
        'longName': user.get('longName'),
        'shortName': user.get('shortName'),
        'macaddr': macaddr_b64,
        'hwModel': user.get('hwModel'),
        'publicKey': pubkey_b64,
        'role': user.get('role'),
        'lastHeard': node_info.get('lastHeard'),
        'snr': node_info.get('snr'),
        'hopsAway': node_info.get('hopsAway')
    }
    node_list.append(node_data)

# Sort by node ID
node_list.sort(key=lambda x: x['num'])

# Output JSON
print(json.dumps(node_list, indent=2))

iface.close()
