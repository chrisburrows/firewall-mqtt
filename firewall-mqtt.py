#!/usr/bin/python3
#
# requirements.txt
#   paho-mqtt
#   netfilter
#

import os
import logging
import logging.handlers
import time
import json
import platform
import subprocess
import paho.mqtt.client as mqtt
from netfilter.rule import Rule
from netfilter.table import Table

LOG_FILENAME = '/var/log/firewall-mqtt.log'
HA_ICON = "mdi:wall"
UPDATE_INTERVAL = int(os.getenv("UPDATE_INTERVAL", "30"))

MQTT_BROKER = os.getenv("MQTT_BROKER", "mqtt.home")
MQTT_USER = os.getenv("MQTT_USER", "mqtt")
MQTT_PASSWORD = os.getenv("MQTT_PASSWORD", "password")
MQTT_BASE_TOPIC = "firewall"

# Acceptance Rule
ACCEPT = Rule(
    jump='ACCEPT'
)

# Acceptance Rule
DROP = Rule(
    jump='DROP'
)

NETFILTER_CHAINS = {
    "lan": { "net-chain": "LAN-TO-NET",          "isolate": "ISOLATE-LAN",   "internet-enabled": True},
    "iot": { "net-chain": "IOT-TO-NET",          "isolate": "ISOLATE-IOT",   "internet-enabled": True},
    "not": { "net-chain": "NOT-TO-NET",          "isolate": "ISOLATE-NOT",   "internet-enabled": False},
    "vpn": { "net-chain": "VPN-TO-NET",          "isolate": "ISOLATE-VPN",   "internet-enabled": True},
    "voice": { "net-chain": "ASSISTANTS-TO-NET", "isolate": "ISOLATE-VOICE", "internet-enabled": True},
    "cloud": { "net-chain": "CLOUD-TO-NET",      "isolate": "ISOLATE-CLOUD", "internet-enabled": True},
    "guest": { "net-chain": "GUEST-TO-NET",      "isolate": "ISOLATE-GUEST", "internet-enabled": True},
    }

def permit_access(table, chain):
    '''Permit access by adding a rule to the chain'''

    log.info("FW: Permitting access for " + chain)
    table.flush_chain(chain)
    table.append_rule(chain, ACCEPT)

def block_access(table, chain):
    '''Deny access by adding a rule to the chain'''

    log.info("FW: Denying access for " + chain)
    table.flush_chain(chain)
    table.append_rule(chain, DROP)

def do_command(table, chain, command):
    '''Set the state of a chain for a named group'''
    if command == 'on':
        permit_access(table, chain)
    elif command == 'off':
        block_access(table, chain)
    else:
        log.info("Illegal command: " + command)


def is_chain_accept_rule(table, chain):
    '''Check if the chain is ACCEPT or empty (DROP)'''
    list = table.list_rules(chain)
    return len(list) == 1 and ACCEPT.specbits() == list[0].specbits()

def publish_status(table, client):
    '''Publish the firewall status to MQTT'''
    log.info("MQTT: Publishing firewall states")
    client.publish(MQTT_BASE_TOPIC + "/status", payload="online")
    for t in NETFILTER_CHAINS.keys():
        topic = "{base}/internet/{t}".format(base=MQTT_BASE_TOPIC, t=t)
        enabled = is_chain_accept_rule(table, NETFILTER_CHAINS[t]["net-chain"])
        client.publish(topic, payload="on" if enabled else "off")

        topic = "{base}/isolation/{t}".format(base=MQTT_BASE_TOPIC, t=t)
        enabled = is_chain_accept_rule(table, NETFILTER_CHAINS[t]["isolate"])
        client.publish(topic, payload="off" if enabled else "on")

def validate_chain(table, chain):
    '''Check to see if the chain is either empty or is just an ACCEPT'''

    list = table.list_rules(chain)
    if len(list) == 0 or len(list) > 1:
      return False
    return ACCEPT.specbits() == list[0].specbits() or DROP.specbits() == list[0].specbits()

def validate_all_chains(table):
    for chain in NETFILTER_CHAINS.values():
        if not validate_chain(table, chain["net-chain"]):
            log.info("Checking Internet access chain " + chain["net-chain"] + " - invalid rules found. Flushing and resetting to default")
            if chain["internet-enabled"]:
                permit_access(table, chain["net-chain"])
            else:
                block_access(table, chain["net-chain"])
        else:
            log.info("Checking Internet access chain " + chain["net-chain"] + " - invalid rules found. Flushing and resetting to default")

        if not validate_chain(table, chain["isolate"]):
            log.info("Checking isolation chain " + chain["isolate"] + " - invalid rules found. Flushing and resetting to enabled")
            permit_access(table, chain["isolate"])
        else:
          log.info("Checking isolation chain " + chain["isolate"] + " - Ok")

# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, rc):
    log.info("MQTT: Connected to broker with result code " + str(rc))

    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    client.publish(MQTT_BASE_TOPIC + "/status", payload="online")

    for t in NETFILTER_CHAINS.keys():
        client.subscribe(MQTT_BASE_TOPIC + "/internet/" + t + "/set")
        client.subscribe(MQTT_BASE_TOPIC + "/isolation/" + t + "/set")

# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
    log.info("MQTT: Message " + msg.topic + " = " + str(msg.payload, "UTF-8"))
    parts = msg.topic.split('/')
    if len(parts) == 4 and parts[1] == "internet" and parts[3] == "set":
        if parts[2] in NETFILTER_CHAINS:
            do_command(userdata, NETFILTER_CHAINS[parts[2]]["net-chain"], str(msg.payload, "UTF-8"))
            publish_status(table, client)
    if len(parts) == 4 and parts[1] == "isolation" and parts[3] == "set":
        if parts[2] in NETFILTER_CHAINS:
            do_command(userdata, NETFILTER_CHAINS[parts[2]]["isolate"], "on" if str(msg.payload, "UTF-8") == "off" else "off")
            publish_status(table, client)
    
    

def publish_home_assistant_discovery(client, name, isolation=False):
    '''Publish discovery for a single firewall rule / switch'''
    if isolation:
      payload = {
        "name": "Firewall Net Isolation {name}".format(name=name.upper()),
        "command_topic": "{base}/isolation/{name}/set".format(base=MQTT_BASE_TOPIC, name=name),
        "state_topic": "{base}/isolation/{name}".format(base=MQTT_BASE_TOPIC, name=name),
        "availability_topic": "{base}/status".format(base=MQTT_BASE_TOPIC),
        "payload_available": "online",
        "payload_not_available": "offline",
        "payload_on": "on",
        "payload_off": "off",
        "unique_id": "{host}-{chain}-isolation".format(host=platform.node(), chain=name),
        "icon": HA_ICON
      }
      discovery_topic = "homeassistant/switch/firewall-isolation-{name}/config".format(name=name)
    else:
      payload = {
        "name": "Firewall Net Access {name}".format(name=name.upper()),
        "command_topic": "{base}/internet/{name}/set".format(base=MQTT_BASE_TOPIC, name=name),
        "state_topic": "{base}/internet/{name}".format(base=MQTT_BASE_TOPIC, name=name),
        "availability_topic": "{base}/status".format(base=MQTT_BASE_TOPIC),
        "payload_available": "online",
        "payload_not_available": "offline",
        "payload_on": "on",
        "payload_off": "off",
        "unique_id": "{host}-{chain}".format(host=platform.node(), chain=name),
        "icon": HA_ICON
      }
      discovery_topic = "homeassistant/switch/firewall-net-access-{name}/config".format(name=name)
    client.publish(discovery_topic, json.dumps(payload))

def home_assistant_discovery(client):
    '''Publish HA discovery'''
    payload = {
        "name": "Firewall Internet Access",
        "state_topic": "{base}/internet".format(base=MQTT_BASE_TOPIC),
        "availability_topic": "{base}/status".format(base=MQTT_BASE_TOPIC),
        "payload_available": "online",
        "payload_not_available": "offline",
        "payload_on": "online",
        "payload_off": "offline",
        "unique_id": "{host}-internet-access".format(host=platform.node()),
        "device_class": "connectivity"
    }
    discovery_topic = "homeassistant/binary_sensor/firewall-net-access/config"
    client.publish(discovery_topic, json.dumps(payload))

    for name in NETFILTER_CHAINS.keys():
        publish_home_assistant_discovery(client, name, isolation=False)
        publish_home_assistant_discovery(client, name, isolation=True)

def ping_test(client):
    '''Ping somegthing to check Internet access is up'''
    status = "online" if subprocess.run(["ping", "-c", "1", "8.8.8.8"], capture_output=True).returncode == 0 else "offline"
    client.publish(MQTT_BASE_TOPIC + "/internet", status)
    log.info("Testing Internet access: " + status)

# setup logging
log = logging.getLogger()
handler = logging.handlers.TimedRotatingFileHandler(LOG_FILENAME, when='midnight', backupCount=7)
formatter = logging.Formatter('{asctime} {levelname:8s} {message}', style='{')

handler.setFormatter(formatter)
log.addHandler(handler)
log.setLevel(logging.DEBUG)
log.info("Starting up...")

# Initialise access to Netfilter tables
table = Table('filter')

# Validate and cleanup chains
validate_all_chains(table)

try:
    # Initialise connect to MQTT broker
    client = mqtt.Client(client_id="firewall")
    client.will_set(MQTT_BASE_TOPIC + "/status", payload="offline")
    client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    client.on_connect = on_connect
    client.on_message = on_message

    while(True):
        log.info("MQTT: Connecting to broker")

        try:
            client.connect(MQTT_BROKER, 1883, 60)

            # set the Netfilter table as the userdata so it's available in call backs
            client.user_data_set(table)
            client.loop_start()

            # mark us as online
            log.info("MQTT: Updating firewall states")

            while (True):
                log.info("MQTT: Publishing HA discovery data")
                home_assistant_discovery(client)

                publish_status(table, client)
                ping_test(client)
                time.sleep(UPDATE_INTERVAL)

        except ConnectionRefusedError:
            log.error("Failed to connect to broker on {ip}:{port}".format(ip=MQTT_BROKER, port=MQTT_PORT))
            time.sleep(30)
    
except KeyboardInterrupt:
    log.info("Interrupted... shutting down")

# mark us offline and disconnect
log.info("MQTT: Publishing offline status")

client.publish(MQTT_BASE_TOPIC + "/status", payload="offline")
time.sleep(3)

log.info("MQTT: disconnecting")
client.loop_stop()
client.disconnect()

