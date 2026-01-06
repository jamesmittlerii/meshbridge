#!/bin/bash

# Load configuration
if [ -f .env ]; then
    export $(grep -v '^#' .env | xargs)
fi

./decode_new.py | \
jq -c --unbuffered 'select(.to == "!ffffffff" and .portnum == "NODEINFO_APP")' | \
while read -r line; do
    # Skip empty lines or lines that don't look like JSON
    if [[ -z "$line" || ! "$line" =~ ^\{ ]]; then
        continue
    fi
    
    # Extract raw payload using jq safely
    raw=$(echo "$line" | jq -r .raw 2>/dev/null)
    payload=$(echo "$line" | jq -c .payload 2>/dev/null) # Use -c for one-line string
    topic=$(echo "$line" | jq -r .topic 2>/dev/null)
    
    if [ "$raw" != "null" ] && [ -n "$raw" ]; then
        # Log timestamp and summary
        echo "$(date '+%Y-%m-%d %H:%M:%S') Relaying Payload: $payload" >&2
        
        # Decode and Publish to Local MQTT
        echo "$raw" | base64 --decode | mosquitto_pub \
            -h "$LOCAL_MQTT_HOST" \
            -u "$LOCAL_MQTT_USER" \
            -P "$LOCAL_MQTT_PASS" \
            -t "$LOCAL_MQTT_TOPIC" \
            -s
    fi
done