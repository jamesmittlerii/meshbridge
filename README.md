# MeshBridge: Remote Node Key Ingestor

**MeshBridge** solves a specific problem in Meshtastic networks: **Acquiring public keys from remote nodes without bridging the entire mesh.**

By default, to send encrypted DMs to a remote node, your radio needs their Public Key. If your radio is not directly connected to their mesh (via RF or a full MQTT gateway), it never sees their `NODEINFO` packets and thus never learns their key.

This tool acts as a selective "Node-Only" bridge. It listens to a remote MQTT stream, filters **only** for `NODEINFO` packets, and replays them into your local radio via a specific "Backdoor" MQTT topic.

## Usage Workflow

1.  **Listen:** Connects to a remote MQTT broker (e.g., Utah Mesh).
2.  **Decode:** Decrypts the private channel traffic (Freq51) using the known PSK.
3.  **Filter:** Selects **only** Broadcast NodeInfo packets (`portnum=NODEINFO_APP`, `to=!ffffffff`).
4.  **Inject:** Re-publishes these packets to your **Local** MQTT broker, targeted specifically at your radio.
5.  **Ingest:** Your radio receives the packet, decrypts it, and adds the remote node (and its Public Key) to its local database.
6.  **Silence:** By injecting into a channel configured with `downlink_enabled=false` (or just by nature of the targeted injection), we prevent re-broadcasting this remote traffic onto your local RF mesh.

## Components

*   `decode.py`: A Python script that connects to MQTT, handles AES-256 decryption (including Meshtastic's custom MQTT key substitution rules), and outputs decrypted packets as JSON stream.
*   `pipeit.sh`: A shell pipeline that runs `decode.py`, filters the stream using `jq`, and pipes the raw payloads to `mosquitto_pub` for local injection.

## Configuration

Configuration is handled via a `.env` file (not committed to repo):

```ini
# Remote MQTT (Source)
MQTT_HOST=mqtt.meshtastic.org
MQTT_TOPICS=msh/US/UT/2/e/Freq51/#
MQTT_USERNAME=meshdev
MQTT_PASSWORD=large4cats

# Decryption Keys
# The PSK for the channel you are monitoring (e.g., Freq51)
MESHTASTIC_PSK=1PG7OiApB1nwvP+rz05p1A==

# Local MQTT (Target)
# Your local broker that your radio is connected to
LOCAL_MQTT_HOST=192.168.4.187
LOCAL_MQTT_USER=mesh
LOCAL_MQTT_PASS=mesh

# Injection Target
# Usually your Radio's ID to force ingestion without broadcast
LOCAL_MQTT_TOPIC=msh/US/2/e/Freq51/!69854258
```

## Running

Ensure you have dependencies installed:
```bash
pip install -r requirements.txt
# Requirements: paho-mqtt, cryptography, protobuf, meshtastic
sudo apt install jq mosquitto-clients
```

Start the bridge:
```bash
./pipeit.sh
```

## License
MIT
