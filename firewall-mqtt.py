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
UPDATE_INTERVAL = int(os.getenv("UPDATE_INTERVAL", "60"))

MQTT_BROKER = os.getenv("MQTT_BROKER", "mqtt.home")
MQTT_USER = os.getenv("MQTT_USER", "mqtt")
MQTT_PASSWORD = os.getenv("MQTT_PASSWORD", "password")
MQTT_BASE_TOPIC = "firewall/" + platform.node()

# Acceptance Rule
ACCEPT = Rule(
    jump='ACCEPT'
)

# Return
RETURN = Rule(
    jump='RETURN'
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


def permit_access(table: str, chain: str) -> None:
    """Permit access by adding a rule to the chain"""

    log.info("FW: Permitting access for " + chain)
    table.flush_chain(chain)
    table.append_rule(chain, ACCEPT)


def block_access(table: str, chain: str) -> None:
    """Deny access by adding a rule to the chain"""

    log.info("FW: Denying access for " + chain)
    table.flush_chain(chain)
    table.append_rule(chain, DROP)


def do_command(table: str, chain: str, state: str, rule: str) -> None:
    """Set the state of a chain for a named group"""
    log.info("FW: Setting chain {chain} to {state}".format(chain=chain, state=state))
    table.flush_chain(chain)
    table.append_rule(chain, rule)


def is_chain_drop_rule(table: str, chain: str) -> bool:
    """Check if the chain is DROP"""
    list = table.list_rules(chain)
    return len(list) == 1 and DROP.specbits() == list[0].specbits()


def publish_status(table: str, client: str) -> None:
    """Publish the firewall status to MQTT"""
    log.info("MQTT: Publishing firewall states")
    client.publish(MQTT_BASE_TOPIC + "/status", payload="online", retain=True)
    for t in NETFILTER_CHAINS.keys():
        topic = "{base}/internet/{t}".format(base=MQTT_BASE_TOPIC, t=t)
        denied = is_chain_drop_rule(table, NETFILTER_CHAINS[t]["net-chain"])
        client.publish(topic, payload="off" if denied else "on", retain=True)

        topic = "{base}/isolation/{t}".format(base=MQTT_BASE_TOPIC, t=t)
        enabled = is_chain_drop_rule(table, NETFILTER_CHAINS[t]["isolate"])
        client.publish(topic, payload="on" if enabled else "off", retain=True)


def validate_chain(table: str, chain: str, is_isolation: bool = False) -> bool:
    """Check to see if the chain is either empty or is just an ACCEPT"""

    list = table.list_rules(chain)
    if len(list) == 0 or len(list) > 1:
      return False
    if is_isolation:
        return RETURN.specbits() == list[0].specbits() or DROP.specbits() == list[0].specbits()
    else:
        return ACCEPT.specbits() == list[0].specbits() or DROP.specbits() == list[0].specbits()


def validate_all_chains(table: str) -> None:
    for chain in NETFILTER_CHAINS.values():
        if not validate_chain(table, chain["net-chain"], False):
            log.info("Checking Internet access chain " + chain["net-chain"] + " - invalid rules found. Flushing and resetting to default")
            if chain["internet-enabled"]:
                do_command(table, chain["net-chain"], "on", ACCEPT)
            else:
                do_command(table, chain["net-chain"], "off", DROP)
        else:
            log.info("Checking Internet access chain " + chain["net-chain"] + " - invalid rules found. Flushing and resetting to default")

        if not validate_chain(table, chain["isolate"], True):
            log.info("Checking isolation chain " + chain["isolate"] + " - invalid rules found. Flushing and resetting to enabled")
            do_command(table, chain["isolate"], "off", RETURN)
        else:
          log.info("Checking isolation chain " + chain["isolate"] + " - Ok")


# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, rc) -> None:
    log.info("MQTT: Connected to broker with result code " + str(rc))

    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    client.publish(MQTT_BASE_TOPIC + "/status", payload="online", retain=True)
    client.will_set(MQTT_BASE_TOPIC + "/status", payload="offline", retain=True)

    for t in NETFILTER_CHAINS.keys():
        client.subscribe(MQTT_BASE_TOPIC + "/internet/" + t + "/set")
        client.subscribe(MQTT_BASE_TOPIC + "/isolation/" + t + "/set")


# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg) -> None:
    payload=str(msg.payload, "UTF-8").strip()
    log.info("MQTT: Message " + msg.topic + " = " + payload)
    parts = msg.topic.split('/')
    if len(parts) == 5 and parts[2] == "internet" and parts[4] == "set":
        if parts[3] in NETFILTER_CHAINS:
            chain = NETFILTER_CHAINS[parts[3]]["net-chain"]
            state = payload
            rule = ACCEPT if state == "on" else DROP
    if len(parts) == 5 and parts[2] == "isolation" and parts[4] == "set":
        if parts[3] in NETFILTER_CHAINS:
            chain = NETFILTER_CHAINS[parts[3]]["isolate"]
            state = payload
            rule = RETURN if state == "off" else DROP

    do_command(userdata, chain, state, rule)
    publish_status(table, client)
    

def publish_home_assistant_discovery(client, name: str, isolation: bool = False) -> None:
    '''Publish discovery for a single firewall rule / switch'''
    if isolation:
      payload = {
        "name": "Firewall {host} Net Isolation {name}".format(host=platform.node().capitalize(), name=name.upper()),
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
      discovery_topic = "homeassistant/switch/firewall-{host}-isolation-{name}/config".format(host=platform.node(), name=name)
    else:
      payload = {
        "name": "Firewall {host} Net Access {name}".format(host=platform.node().capitalize(), name=name.upper()),
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
      discovery_topic = "homeassistant/switch/firewall-{host}-net-access-{name}/config".format(host=platform.node(), name=name)
    client.publish(discovery_topic, json.dumps(payload), retain=True)


def home_assistant_discovery(client):
    """Publish HA discovery"""
    for name in NETFILTER_CHAINS.keys():
        publish_home_assistant_discovery(client, name, isolation=False)
        publish_home_assistant_discovery(client, name, isolation=True)


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
    client = mqtt.Client(client_id="firewall-{host}".format(host=platform.node()))
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

            log.info("MQTT: Publishing HA discovery data")
            home_assistant_discovery(client)

            while True:
                publish_status(table, client)
                time.sleep(UPDATE_INTERVAL)

        except ConnectionRefusedError:
            log.error("Failed to connect to broker on {ip}:{port}".format(ip=MQTT_BROKER, port=MQTT_PORT))
            time.sleep(30)
    
except KeyboardInterrupt:
    log.info("Interrupted... shutting down")

# mark us offline and disconnect
log.info("MQTT: Publishing offline status")

client.publish(MQTT_BASE_TOPIC + "/status", payload="offline", retain=True)
time.sleep(3)

log.info("MQTT: disconnecting")
client.loop_stop()
client.disconnect()

